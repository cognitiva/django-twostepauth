from django import forms
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User, SiteProfileNotAvailable
from django.contrib.auth.tokens import default_token_generator
from django.contrib.admin.forms import AdminAuthenticationForm
from django.db.models import get_model
from django.utils.translation import ugettext_lazy as _
from . import settings as twostepauth_settings
from .auth_backend import TwoStepAuthBackend

#from django-profiles
def get_profile_model():
    """
    Return the model class for the currently-active user profile
    model, as defined by the ``AUTH_PROFILE_MODULE`` setting. If that
    setting is missing, raise
    ``django.contrib.auth.models.SiteProfileNotAvailable``.

    """
    if (not hasattr(settings, 'AUTH_PROFILE_MODULE')) or \
           (not settings.AUTH_PROFILE_MODULE):
        raise SiteProfileNotAvailable
    profile_mod = get_model(*settings.AUTH_PROFILE_MODULE.split('.'))
    if profile_mod is None:
        raise SiteProfileNotAvailable
    return profile_mod


def get_profile_form():
    """
    Returns a profile model form without the two-step authentication fields
    """
    profile_mod = get_profile_model()
    class _ProfileForm(forms.ModelForm):
        class Meta:
            model = profile_mod
            exclude = ('user', 'tsa_active', 'tsa_secret', 'tsa_backup_codes', 
                       'tsa_hotp_counter', 'tsa_skew')
    return _ProfileForm


TWOSTEPAUTH_METHOD_OPTIONS = (
    ('APP', 'Mobile App'),
    ('BACKUP', 'Backup codes'),
)


class TwoStepAuthenticationForm(AuthenticationForm):
    """
    Form for the first step of login in the two-step authentication process.
    """
    def __init__(self, *args, **kw):
        if kw.has_key('remember_token'):
            self.remember_token = kw['remember_token']
            del kw['remember_token']
        else:
            self.remember_token = None
        self.user = None
        self.usertoken = None
        super(TwoStepAuthenticationForm, self).__init__(*args, **kw)

    def clean(self):
        """
        Checks for the username and password.

        If the user cannot be authenticated tries to generate the user token 
        for the second step of the authentication process. If the token cannot 
        be generated a validation error is raised.

        If the user is not active a validation error is raised.
        """
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')

        if username and password:
            force_single_step = not twostepauth_settings.TWOSTEPAUTH_FOR_USERS
            self.user = authenticate(username=username, password=password, 
                            remember_token=self.remember_token, 
                            force_single_step=force_single_step)
            if self.user is None:
                # see if this guy has two-step auth enabled
                self.usertoken = TwoStepAuthBackend().first_step(
                                        username=username, password=password)
                if self.usertoken is None:
                    raise forms.ValidationError(_("Please enter a correct username and password. Note that both fields are case-sensitive."))
            elif not self.user.is_active:
                raise forms.ValidationError(_("This account is inactive."))
        self.check_for_test_cookie()
        return self.cleaned_data

    def get_user(self):
        """
        Returns the authenticated user object if authentication was done, 
        otherwise it will be None
        """
        return self.user


class TokenAuthenticationForm(forms.Form):
    """
    Form for the second step of login in the two-step authentication process
    where the application code or backup codes are entered to complete the
    authentication.
    """
    code = forms.IntegerField(label=_("Authentication Code"),
        help_text=_(u"If you have enabled two-factor authentication, enter the "
            "six-digit number from your authentication device here."),
        widget=forms.TextInput(attrs={'maxlength':'8'}),
        min_value=0, max_value=99999999,
        required=True
    )
    method = forms.CharField(label=_("Authentication method"),
                             widget=forms.Select(choices = TWOSTEPAUTH_METHOD_OPTIONS),
                             required = True,
                            )
    remember_computer = forms.BooleanField(widget=forms.CheckboxInput(),
                               required=False,
                               initial=False,
                               label=_(u'Remember this computer for %(days)s days') % {'days': twostepauth_settings.TWOSTEPAUTH_REMEMBER_COMPUTER_DAYS})
    authkey = forms.CharField(widget=forms.HiddenInput())
    username = forms.CharField(widget=forms.HiddenInput())
    remember = forms.BooleanField(widget=forms.HiddenInput(), required=False)

    def clean(self):
        code = self.cleaned_data.get('code')
        method = self.cleaned_data.get('method')
        username = self.cleaned_data.get('username')
        authkey = self.cleaned_data.get('authkey')

        if method == 'APP' and code > 999999:
            raise forms.ValidationError(_(u"Wrong authentication code format"))

        self.user = authenticate(username=username, code=code, method=method, token=authkey)
        if not self.user:
            raise forms.ValidationError(_(u"User authentication failed"))
        
        return self.cleaned_data

    def get_user(self):
        """
        Returns the authenticated user object if authentication was done, 
        otherwise it will be None
        """
        return self.user


class TwoStepAuthEditForm(forms.Form):
    """
    Form for use in the user profile to activate/inactivate the use of two-step
    authentication.
    """
    tsa_active = forms.BooleanField(widget=forms.CheckboxInput(),
                                    required=False,
                                    label=_(u'Two-Step Authentication'))


class SingleStepAdminAuthenticationForm(AdminAuthenticationForm):
    """
    Form for authentication in the admin section of the site when the 
    two-step auth is disabled by the ``TWOSTEPAUTH_FOR_ADMIN`` setting.
    """
    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        message = _("Please enter a correct username and password. "
                    "Note that username and password fields are case-sensitive.")
        if username and password:
            try:
                user = User.objects.get(username=username)
            except (User.DoesNotExist, User.MultipleObjectsReturned):
                raise forms.ValidationError(message)
            self.user_cache = authenticate(username=username, password=password, 
                                           force_single_step=True)
            if self.user_cache is None:
                raise forms.ValidationError(message)
            elif not self.user_cache.is_active or not self.user_cache.is_staff:
                raise forms.ValidationError(message)
        self.check_for_test_cookie()
        return self.cleaned_data


class TwoStepAdminAuthenticationForm(AdminAuthenticationForm):
    """
    Form forauthentication in the admin section of the site when the 
    two-step auth is enabled by the ``TWOSTEPAUTH_FOR_ADMIN`` setting.
    """
    code = forms.IntegerField(label=_("Authentication Code"),
        help_text=_(u"If you have enabled two-factor authentication, enter the "
            "six-digit number from your authentication device here."),
        widget=forms.TextInput(attrs={'maxlength':'8'}),
        min_value=0, max_value=99999999,
        required=False
    )
    method = forms.CharField(label=_("Authentication method"),
                             widget=forms.Select(choices = TWOSTEPAUTH_METHOD_OPTIONS),
                             required = True,
                            )
    remember_computer = forms.BooleanField(widget=forms.CheckboxInput(),
                               required=False,
                               initial=True,
                               label=_(u'Remember this computer for %(days)s days') % {
                                'days': twostepauth_settings.TWOSTEPAUTH_REMEMBER_COMPUTER_DAYS})

    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        code = self.cleaned_data.get('code')
        method = self.cleaned_data.get('method')

        #app token codes have 6 digits
        if method == 'APP' and code > 999999:
            raise forms.ValidationError(_(u"Wrong authentication code format"))

        message = _("Please enter a correct username, password and token. "
                    "Note that username and password fields are case-sensitive.")
        
        if username and password:
            try:
                user = User.objects.get(username=username)
            except (User.DoesNotExist, User.MultipleObjectsReturned):
                raise forms.ValidationError(message)
            try:
                profile = user.get_profile()
            except:
                profile = None
            
            if profile and profile.tsa_active:
                self.user_cache = authenticate(username=username, password=password, 
                                               code=code, method=method)
            else:
                self.user_cache = authenticate(username=username, password=password)

            if self.user_cache is None:
                raise forms.ValidationError(message)
            elif not self.user_cache.is_active or not self.user_cache.is_staff:
                raise forms.ValidationError(message)
        self.check_for_test_cookie()
        
        return self.cleaned_data