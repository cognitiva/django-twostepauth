from django.views.generic.base import TemplateView
from django.conf.urls.defaults import patterns, include, url
from django.conf import settings
from django.contrib import admin

from twostepauth.forms import get_profile_form

admin.autodiscover()

urlpatterns = patterns('',
    url(r'^admin/', include(admin.site.urls)),
    url(r'^accounts/login/$',
           'twostepauth.views.login_step_one',
           {'template_name':'registration/login.html'},
           name='auth_login'),
   url(r'^accounts/login/step_two$',
           'twostepauth.views.login_step_two',
           name='login_step_two'),
    #registration
    (r'^accounts/', include('registration.urls')),
    #profiles
    url(r'^profiles/twostepauth/$', 'twostepauth.views.twostepauth_profile', name='twostepauth_profile'),
    url(r'^profiles/edit/$', 'profiles.views.edit_profile', 
            {'form_class': get_profile_form() }, name='profiles_edit_profile'),
    (r'^profiles/', include('profiles.urls')),
    #demo application
    url(r'^', TemplateView.as_view(template_name="index.html"), name='home'),
)

if settings.DEBUG:
    urlpatterns += patterns('',
        (r'^media/(?P<path>.*)$',
         'django.views.static.serve',
         {'document_root': settings.MEDIA_ROOT, 'show_indexes': True, }),
)
