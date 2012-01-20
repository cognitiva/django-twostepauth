#coding: utf-8
from django.contrib import admin
from .models import BlockedTimestamp, ResettingTimeSkew
from .forms import TwoStepAdminAuthenticationForm, SingleStepAdminAuthenticationForm
from . import settings as twostepauth_settings

#change the admin forms to support two-step admin
if twostepauth_settings.TWOSTEPAUTH_FOR_ADMIN:
    admin.site.login_form = TwoStepAdminAuthenticationForm
    admin.site.login_template = 'twostepauth/adminlogin.html'
else:
    admin.site.login_form = SingleStepAdminAuthenticationForm

admin.site.register(BlockedTimestamp)
admin.site.register(ResettingTimeSkew)