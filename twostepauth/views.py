#coding: utf-8
import urlparse
import urllib
from datetime import datetime, timedelta
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth import REDIRECT_FIELD_NAME, login as auth_login
from django.contrib.auth.models import User
from django.contrib.sites.models import get_current_site
from django.core.exceptions import ObjectDoesNotExist
from django.core.urlresolvers import reverse
from django.http import HttpResponse, Http404, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.shortcuts import redirect, get_object_or_404
from django.template import RequestContext
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.generic.simple import direct_to_template

from .forms import TwoStepAuthEditForm, TokenAuthenticationForm, TwoStepAuthenticationForm
from .utils import build_chart_url, RememberComputerTokenGenerator
from . import settings as twostepauth_settings


@login_required
def twostepauth_profile(request, edit_form=TwoStepAuthEditForm,
                        template_name='twostepauth/profile.html', extra_context=None, **kwargs):
    """
    Allow the user to view and change the Two-Step authentication settings from his profile.

    **Optional arguments:**

    ``edit_form``
        The form class to use for validating and saving the profile. If not supplied,
        it will default to TwoStepAuthEditForm

    ``template_name``
        The template to use when displaying the profile-editing form.
        If not supplied, it will default to :template:`twostepauth/profile.html`.

    ``extra_context``
        A dictionary with extra parameter that will be included in the context.
        Defaults to None

    **Context:**

    ``form``
        The profile-editing form.

    ``profile``
        The user's profile.

    ``chart_url``
        The URL for the QRCode of the user's secret if Two-Step authentication is
        active. None otherwise.
    """
    user = request.user
    #only display if two-step authentication is enabled
    if not twostepauth_settings.TWOSTEPAUTH_FOR_USERS:
        raise Http404

    try:
        profile = user.get_profile()
    except ObjectDoesNotExist:
        raise Http404

    if request.method == 'POST':
        form = edit_form(data=request.POST)
        if form.is_valid():
            profile.tsa_active = form.cleaned_data['tsa_active']
            profile.save()
            redirect_to = reverse('twostepauth_profile')
            return redirect(redirect_to)
    else:
        form = edit_form(initial={'tsa_active': profile.tsa_active})

    ctx = extra_context if extra_context else dict()
    ctx.update(dict(profile=profile, form=form))
    if profile.tsa_active:
        site = get_current_site(request)
        ctx['chart_url'] = build_chart_url(profile.tsa_secret, user.username, site.domain)
    else:
        ctx['chart_url'] = None
    return render_to_response(template_name, ctx,
                              context_instance=RequestContext(request))


@never_cache
def login_step_one(request, authentication_form=TwoStepAuthenticationForm,
           template_name='twostepauth/login.html',
           redirect_field_name=REDIRECT_FIELD_NAME,
           extra_context=None
           ):
    """
    First step of the login process: ask for username and password.

    **Optional arguments:**

    ``authentication_form``
        The form class to use for validating the user. If not supplied,
        it will default to TwoStepAuthenticationForm.

    ``template_name``
        The template to use when displaying the username and password form.
        If not supplied, it will default to :template:`twostepauth/login.html`.

    ``redirect_field_name``
        The name of the query string parameter containing the path that the user should be redirected to upon successful authentication.
        If not supplied, it will default to django.contrib.auth.REDIRECT_FIELD_NAME

    ``extra_context``
        A dicionary of extra parameters to be included in the Context. Defaults to None.


    **Context:**
    ``form``
        The user-authentication form.

    ``redirect_field_name``
        The name of the field that should containi the path that the user should be redirected to upon successful authentication.

    ``site``
        The current Site.

    ``site_name``
        The name of the current Site.
    """
    redirect_to = request.REQUEST.get(redirect_field_name, '')
    if not extra_context:
        extra_context = {}
    
    if request.method == 'POST':
        remember_token = request.COOKIES.get(twostepauth_settings.TWOSTEPAUTH_SESSION_KEY, None)
        form = authentication_form(data=request.POST, remember_token=remember_token)

        if form.is_valid():
            user = form.user
            #the user token will be inactivated after the first login
            #since it uses the user.last_login field
            usertoken = form.usertoken

            if usertoken:
                qs = { 'authkey':usertoken, 'username': request.POST['username'],
                       'next': request.REQUEST.get(redirect_field_name, ''),
                       'remember': form.cleaned_data.get('remember', '')
                      }
                next_step_redirect = reverse('twostepauth.views.login_step_two')   
                return HttpResponseRedirect('%s?%s' % (next_step_redirect, urllib.urlencode(qs)))

            elif user and user.is_active:
                netloc = urlparse.urlparse(redirect_to)[1]

                # Use default setting if redirect_to is empty
                if not redirect_to:
                    redirect_to = settings.LOGIN_REDIRECT_URL

                # Security check -- don't allow redirection to a different
                # host.
                elif netloc and netloc != request.get_host():
                    redirect_to = settings.LOGIN_REDIRECT_URL

                # Okay, security checks complete. Log the user in.
                auth_login(request, form.get_user())

                if request.session.test_cookie_worked():
                    request.session.delete_test_cookie()

                return HttpResponseRedirect(redirect_to)
    else:
        form = authentication_form(request)

    request.session.set_test_cookie()

    current_site = get_current_site(request)
    extra_context.update({'form': form,
                          redirect_field_name: redirect_to,
                          'site': current_site,
                          'site_name': current_site.name})
    return direct_to_template(request, template_name,
                              extra_context=extra_context)


@never_cache
def login_step_two(request, token_form=TokenAuthenticationForm,
                        template_name='twostepauth/signin_token_form.html',
                        redirect_field_name=REDIRECT_FIELD_NAME,
                        extra_context=None):
    """
    Displays the second step of the two-step authentication process.


    **Optional arguments:**


    ``token_form``
        The form class to use for the second step of the authentication where
        the user inputs the token code. If not supplied it will default to
        TokenAuthenticationForm.

    ``template_name``
        The template to use when displaying the one-time code form.
        If not supplied, it will default to :template:`twostepauth/signin_token_form.html`.

    ``redirect_field_name``
        The name of the query string parameter containing the path that the user should be redirected to upon successful authentication.
        If not supplied, it will default to django.contrib.auth.REDIRECT_FIELD_NAME

    ``extra_context``
        A dicionary of extra parameters to be included in the Context. Defaults to None.


    **Context:**
    ``form``
        The token validation form.
    """
    if not extra_context:
        extra_context = {}

    if request.method == 'POST':
        redirect_to = request.REQUEST.get(redirect_field_name, '')
        form = token_form(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            #login_remember(request, user, form.cleaned_data.get('remember',False))
            # Use default setting if redirect_to is empty
            if not redirect_to:
                redirect_to = settings.LOGIN_REDIRECT_URL

            # Security check -- don't allow redirection to a different
            # host.
            elif netloc and netloc != request.get_host():
                redirect_to = settings.LOGIN_REDIRECT_URL

            auth_login(request, user)
            response = HttpResponseRedirect(redirect_to)
            remember_computer = form.cleaned_data.get('remember_computer', False)
            if remember_computer:
                #with Django 1.4 this can be replaced by the signed cookie
                token_generator = RememberComputerTokenGenerator()
                token_remember = token_generator.make_token(user)
                dt = datetime.now() + timedelta(twostepauth_settings.TWOSTEPAUTH_REMEMBER_COMPUTER_DAYS)
                response.set_cookie(twostepauth_settings.TWOSTEPAUTH_SESSION_KEY,
                                    token_remember, expires=dt)
            return response
    else:
        initial_data = {
            'authkey': request.GET.get('authkey',''),
            'username': request.GET.get('username',''),
            'next': request.GET.get(redirect_field_name, ''),
            'remember': request.GET.get('remember', False),
            }
        form = token_form(initial=initial_data)

    extra_context.update({'form': form})
    return direct_to_template(request, template_name,
                              extra_context=extra_context)
