from django.core.management.base import BaseCommand, CommandError
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.models import SiteProfileNotAvailable
from django.contrib.auth.models import User
from ...utils import generate_secret


class Command(BaseCommand):
    args = '<username>'
    help = 'Activate Two-Step Authentication, generate a secret and store it in the database'

    def handle(self, *args, **options):
        if not args:
            raise CommandError("Username missing.")
        username = args[0]  # FIXME what if no args?
        try:
            user = User.objects.get(username=username)
        except:
            raise CommandError("No such user.")
        try:
            p = user.get_profile()
        except (ObjectDoesNotExist, SiteProfileNotAvailable):
            # we do not create a profile because it might have application-dependent
            # fields we know nothing about
            raise CommandError("%s does not have a profile.\n" % (username))
        secret = generate_secret()
        p.tsa_active = True
        p.tsa_secret = secret
        p.save()
        self.stdout.write("%s's secret: %s\n" % (username, secret))
