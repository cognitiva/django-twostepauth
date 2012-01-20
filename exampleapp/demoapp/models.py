from django.db import models
from twostepauth.models import TwoStepAuthBaseProfile



class UserProfile(TwoStepAuthBaseProfile):
    user = models.OneToOneField('auth.User')
    website = models.CharField(max_length=255, blank=True)

    @models.permalink
    def get_absolute_url(self):
        return ('profiles_profile_detail', (), { 'username': self.user.username })

