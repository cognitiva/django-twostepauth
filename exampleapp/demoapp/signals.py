from django.db import models
from django.db.models.signals import post_save
from django.contrib.auth.models import User
from .models import UserProfile

#to automatically create a userprofile when a user is created
def create_profile(sender, **kw):
    user = kw["instance"]
    if kw["created"]:
        profile = UserProfile(user=user)
        profile.save()

post_save.connect(create_profile, sender=User, dispatch_uid="users-profilecreation-signal")
