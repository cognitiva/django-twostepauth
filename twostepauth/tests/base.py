#coding: utf-8
from django.conf import settings
import django.test
from .. import models


# (time, code)
otp_data = (
 (1326200700, '198163'),
 (1326200730, '490687'),
 (1326200760, '169065'),
 (1326200790, '354338'),
 (1326200820, '470117'),
 (1326200850, '254910'),
 (1326200880, '116697'),
 (1326200910, '162848'),
 (1326200940, '041688'),
 (1326200970, '208238'),
)

# (counter, code)
hotp_data = (
 (1, '163197'),
 (2, '463247'),
 (3, '237765'),
 (4, '139813'),
 (5, '861093'),
 (6, '231387'),
)


# patch so we can test time-dependent functions
def get_fake_time_fn():
    def fake_time():
        for time_idx in xrange(len(otp_data)):
            yield otp_data[time_idx][0]
    return fake_time().next


class TwoStepAuthProfileTestCaseBase(django.test.TestCase):
    def tearDown(self):
        """Restores the AUTH_PROFILE_MODULE -- if it was not set it is deleted,
        otherwise the old value is restored"""
        if self.old_AUTH_PROFILE_MODULE is None and \
                hasattr(settings, 'AUTH_PROFILE_MODULE'):
            del settings.AUTH_PROFILE_MODULE

        if self.old_AUTH_PROFILE_MODULE is not None:
            settings.AUTH_PROFILE_MODULE = self.old_AUTH_PROFILE_MODULE

    def setUp(self):
        self.old_AUTH_PROFILE_MODULE = getattr(settings,
                                               'AUTH_PROFILE_MODULE', None)
        settings.AUTH_PROFILE_MODULE = 'twostepauth.TestProfile'


