#FIXME have a default urls on the previous level
#from django.contrib.auth.urls import urlpatterns
from django.conf.urls.defaults import *

#@never_cache
#def remote_user_auth_view(request):
    #"Dummy view for remote user tests"
    #t = Template("Username is {{ user }}.")
    #c = RequestContext(request, {})
    #return HttpResponse(t.render(c))

# special urls for auth test cases
urlpatterns = patterns('',
     # Test the 'activate' view with custom template
     # name.
     url(r'^login/$',
         'twostepauth.views.login_step_one',
         name='auth_login'),
     url(r'^login/step_two/$',
           'twostepauth.views.login_step_two',
           name='login_step_two'),
     url(r'^profiles/twostepauth/$', 'twostepauth.views.twostepauth_profile', name='twostepauth_profile'),
)

"""
patterns('',
    url(r'^admin/', include(admin.site.urls)),
    url(r'^accounts/login/$',
           'twostepauth.views.login_step_one',
           name='auth_login'),
   url(r'^accounts/login/step_two$',
           'twostepauth.views.login_step_two',
           name='login_step_two'),
    #registration
    (r'^accounts/', include('registration.backends.default.urls')),
    #profiles
    url(r'^profiles/twostepauth/$', 'twostepauth.views.twostepauth_profile', name='twostepauth_profile'),
    url(r'^profiles/edit/$', 'profiles.views.edit_profile', 
            {'form_class': get_profile_form() }, name='profiles_edit_profile'),
    (r'^profiles/', include('profiles.urls')),
    #demo application
    url(r'^', direct_to_template, {'template':'index.html'}, name='home'),
)
"""