#coding: utf-8
import base64
import datetime
import os
import time
from urllib import quote
from django.utils import unittest
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth import SESSION_KEY, REDIRECT_FIELD_NAME
from django.db.models import OneToOneField
import django.test
from ..utils import build_chart_url, generate_single_backup_code, generate_secret
from .. import models
from .. import settings as ts_settings
from .auth_backend import TwoStepAuthBackendTestCase
from .base import TwoStepAuthProfileTestCaseBase, otp_data, hotp_data, get_fake_time_fn
from .forms import (TestTwoStepAdminAuthenticationForm, TestSingleStepAdminAuthenticationForm,
            TestTokenAuthenticationForm, TestTwoStepAuthenticationForm, 
            TestTwoStepAuthenticationFormBase)
from .utils import TestBackupCodes, TestRememberComputerTokenGenerator
from .views import TestTwoStepProfile, TestLoginStepOne, TestLoginStepTwo


# To define a model that is only present in the database when testing we can do it here
class TestProfile(models.TwoStepAuthBaseProfile):
    user = OneToOneField('auth.User')
    pass


class UtilsTestCaseBase(unittest.TestCase):
    def setUp(self):
        self.secret = "2SH3V3GDW7ZNMGYE"
        self.username = 'testuser'
        self.hostname = 'www.example.com'

    def get_expected_url(self, username, hostname):
        return 'https://chart.googleapis.com/chart?chl=otpauth%%3A%%2F%%2F%cotp%%2F%s%%40%s%%3Fsecret%%3D%s&chs=200x200&cht=qr&chld=M%%7C0' % (self.otp, username, hostname, self.secret)


# Assumes TWOSTEPAUTH_TOTP = True in settings
class UtilsTestCase(UtilsTestCaseBase):
    otp = 't'

    def test_build_chart_url(self):
        """test"""
        url = build_chart_url(self.secret, self.username, self.hostname)
        expected_url = self.get_expected_url(self.username, self.hostname)
        self.assertEqual(url, expected_url)

    def test_generate_single_backup_code(self):
        numbers = map(str, range(10))
        backup_code = generate_single_backup_code()
        self.assertEqual(len(backup_code), 8)
        for n in backup_code:
            self.assertTrue(n in numbers)
        self.assertNotEqual(backup_code[0], '0')

    def test_generate_secret(self):
        secret = generate_secret()
        decoded_secret = base64.b32decode(secret)
        self.assertEqual(len(decoded_secret), 10)


class HotpUtilsTestCase(UtilsTestCaseBase):
    otp = 'h'

    def setUp(self):
        super(HotpUtilsTestCase, self).setUp()
        self.original_totp_setting = ts_settings.TWOSTEPAUTH_TOTP
        ts_settings.TWOSTEPAUTH_TOTP = False

    def tearDown(self):
        ts_settings.TWOSTEPAUTH_TOTP = self.original_totp_setting

    def test_build_chart_url(self):
        """test"""
        url = build_chart_url(self.secret, self.username, self.hostname)
        expected_url = self.get_expected_url(self.username, self.hostname)
        self.assertEqual(url, expected_url)


class TwoStepAuthProfileTestCase(TwoStepAuthProfileTestCaseBase):
    fixtures = ['test_users.json', ]

    def setUp(self):
        super(TwoStepAuthProfileTestCase, self).setUp()
        self.old_now = models.now
        models.now = get_fake_time_fn()
        self.user_otp = User.objects.get(username='test_otp')
        self.profile = self.user_otp.get_profile()
        self.original_reuse_setting = ts_settings.TWOSTEPAUTH_DISALLOW_REUSE
        ts_settings.TWOSTEPAUTH_DISALLOW_REUSE = True

    def tearDown(self):
        super(TwoStepAuthProfileTestCase, self).tearDown()
        ts_settings.TWOSTEPAUTH_DISALLOW_REUSE = self.original_reuse_setting
        models.now = self.old_now

    def test_validate_totp(self):
        """ test that totp validation works. """
        self.assertTrue(self.profile.validate_totp(otp_data[0][1]))

    def test_validate_totp_wrong_code(self):
        """ test that totp validation fails with an invalid code. """
        self.assertFalse(self.profile.validate_totp('123456'))

    def test_validate_totp_window(self):
        """ Code OK not for the current time, but for a time inside the window. """
        self.assertTrue(self.profile.validate_totp(otp_data[2][1]))

    def test_validate_totp_window(self):
        """ Code OK, but for a time outside the window should fail. """
        self.assertFalse(self.profile.validate_totp(otp_data[9][1]))

    def test_validate_totp_reuse(self):
        """ Test that we cannot reuse the same code. """
        self.assertTrue(self.profile.validate_totp(otp_data[0][1]))
        self.assertFalse(self.profile.validate_totp(otp_data[0][1]))

    def test_validate_totp_skew(self):
        """Test skew parameter to adjust for out of sync clocks"""
        self.assertFalse(self.profile.validate_totp(otp_data[7][1]))
        self.assertFalse(self.profile.validate_totp(otp_data[8][1]))
        # After 3 consecutive codes 
        self.assertTrue(self.profile.validate_totp(otp_data[9][1]))
        # skew = (otp_data[9]/TWOSTEPAUTH_TIME_STEP_SIZE)-(otp_data[2])/TWOSTEPAUTH_TIME_STEP_SIZE)
        self.assertEquals(self.profile.tsa_skew, 7)

    def test_validate_hotp(self):
        """ Hmac-based code OK """
        self.assertTrue(self.profile.validate_hotp(hotp_data[0][1]))

    def test_validate_hotp_wrong_code(self):
        """ Invalid Hmac-based code """
        self.assertFalse(self.profile.validate_hotp('654321'))

    def test_validate_hotp_window(self):
        """ Hmac-based code OK not for the current time, but for time inside the window """
        self.assertTrue(self.profile.validate_hotp(hotp_data[2][1]))

    def test_validate_hotp_window(self):
        """Code OK, but for time outside window"""
        self.assertFalse(self.profile.validate_hotp(hotp_data[5][1]))

    def test_validate_hotp_window_adjust(self):
        """ Test that the HOTP window is properly moved after each try.
        Assumes TWOSTEPAUTH_HOTP_WINDOW_SIZE = 3
        """
        # initially internal hotp counter = 1 ; window = (1, 2, 3)
        # hotp_data[3] has counter == 4, outside of window
        self.assertFalse(self.user_otp.get_profile().validate_hotp(hotp_data[3][1]))
        # now the internal counter is 2, so the window should be (2, 3, 4)
        self.assertTrue(self.user_otp.get_profile().validate_hotp(hotp_data[3][1]))
        # now the internal counter is 4+1=5, because 4 was the one that matched previously
        # so the window should be (5, 6, 7) [instead of (3, 4, 5)]
        # hotp_data[5] has counter == 6, inside the window
        self.assertTrue(self.user_otp.get_profile().validate_hotp(hotp_data[5][1]))
        # counter is now 6+1=7
        self.assertEquals(self.user_otp.get_profile().tsa_hotp_counter, 7)

    def test_validate_hotp_counter_increase(self):
        """Test that the HOTP counter is properly moved after each try."""
        # initially internal hotp counter = 1
        self.assertTrue(self.profile.validate_hotp(hotp_data[0][1]))
        # repeated code will fail; counter is now 2
        self.assertFalse(self.profile.validate_hotp(hotp_data[0][1]))
        # counter is now 3
        self.assertTrue(self.profile.validate_hotp(hotp_data[2][1]))

    def test_compute_code(self):
        """ Test compute_code method """
        code = self.profile.compute_code(7)
        self.assertEquals(code, 31324)

    def test_get_backup_codes(self):
        """ Test get_backup_codes returns a list of integer codes """
        backup_codes = self.profile.get_backup_codes()
        expected = [89683765, 88611506, 92275470, 66332141, 40243962, 31262430, 67871482, 74624078,
            37259719, 87607025]
        self.assertEquals(backup_codes, expected)

    def test_set_backup_codes(self):
        """ Test set_backup_codes sets the code in the database as a ; separated string """
        new_codes = [78339327, 73846888, 84164543, 36870146, 92485331, 15149128, 63228144, 51030528, 30009664]
        expected = "78339327;73846888;84164543;36870146;92485331;15149128;63228144;51030528;30009664"
        self.profile.set_backup_codes(new_codes)
        self.assertEquals(expected, self.profile.tsa_backup_codes)

    def test_invalidate_totp_code(self):
        """ Test that invalidate_totp_code returns True for a valid code and adds it to the blocked list. """
        # in the initial data this user has 1 blocked timestamp (99)
        bt = self.user_otp.blockedtimestamp_set.all()
        self.assertEquals(len(bt), 1)
        self.assertEquals(bt[0].timestamp, 99)
        # 55 is not blocked
        self.assertTrue(self.profile.invalidate_totp_code(55))
        # but after being used it should be blocked
        # 99 is out of the 55 +- TWOSTEPAUTH_TOTP_WINDOW_SIZE window, so it should have been removed from the blocked list
        bt = self.user_otp.blockedtimestamp_set.all()
        self.assertEquals(len(bt), 1)
        self.assertEquals(bt[0].timestamp, 55)

    def test_invalidate_totp_code_blocked(self):
        """ Test that invalidate_totp_code returns False for a blocked code. """
        self.assertFalse(self.profile.invalidate_totp_code(99))

    def test_check_time_skew(self):
        """ Test that check_time_skew identifies 3 consecutive codes and ajdusts skew. """
        self.assertFalse(self.profile.check_time_skew(tm=10, skew=20))
        self.assertEquals(self.user_otp.totp_skew_set.all().count(), 1)
        self.assertFalse(self.profile.check_time_skew(tm=11, skew=20))
        self.assertEquals(self.user_otp.totp_skew_set.all().count(), 2)
        self.assertTrue(self.profile.check_time_skew(tm=12, skew=20))
        self.assertEquals(self.user_otp.totp_skew_set.all().count(), 0)
        self.assertEquals(self.profile.tsa_skew, 20)

    def test_check_time_skew_identical(self):
        """ Test that check_time_skew ignored a repeated code. """
        self.assertFalse(self.profile.check_time_skew(10, 20))
        self.assertEquals(self.user_otp.totp_skew_set.all().count(), 1)
        self.assertFalse(self.profile.check_time_skew(10, 20))
        self.assertEquals(self.user_otp.totp_skew_set.all().count(), 1)

    def test_check_time_skew_not_consecutive(self):
        """ Test that check_time_skew recognizes when the codes are not in quick succession. """
        self.assertFalse(self.profile.check_time_skew(10, 20))
        self.assertEquals(self.user_otp.totp_skew_set.all().count(), 1)
        self.assertFalse(self.profile.check_time_skew(13, 20))
        self.assertEquals(self.user_otp.totp_skew_set.all().count(), 2)
        self.assertFalse(self.profile.check_time_skew(14, 20))
        self.assertEquals(self.user_otp.totp_skew_set.all().count(), 3)

    def test_validate_backup(self):
        """ test that validation of backup codes succeeds. """
        method = 'BACKUP'
        code = 88611506
        self.assertTrue(self.profile.validate(code, method))
        # test code is removed
        self.assertFalse(self.profile.validate(code, method))

    def test_validate_backup_wrong_code(self):
        """ test that validation of backup codes fails with an invalid code. """
        method = 'BACKUP'
        code = 12345678
        self.assertFalse(self.profile.validate(code, method))

    def test_validate_totp(self):
        """ test that validate works when called with a totp """
        method = 'APP'
        code = otp_data[0][1]
        self.assertTrue(self.profile.validate(code, method))


class TwoStepAuthProfileAllowReuseTestCase(TwoStepAuthProfileTestCaseBase):
    fixtures = ['test_users.json', ]

    def setUp(self):
        super(TwoStepAuthProfileAllowReuseTestCase, self).setUp()
        self.user_otp = User.objects.get(username='test_otp')
        self.original_reuse_setting = ts_settings.TWOSTEPAUTH_DISALLOW_REUSE
        ts_settings.TWOSTEPAUTH_DISALLOW_REUSE = False

    def tearDown(self):
        super(TwoStepAuthProfileAllowReuseTestCase, self).tearDown()
        ts_settings.TWOSTEPAUTH_DISALLOW_REUSE = self.original_reuse_setting

    def test_invalidate_totp_code(self):
        """ test that if DISALLOW_REUSE is disabled, a code in the blocked list is accepted """
        self.assertTrue(self.user_otp.get_profile().invalidate_totp_code(99))


class TwoStepAuthProfileHotpTestCase(TwoStepAuthProfileTestCaseBase):
    fixtures = ['test_users.json', ]

    def setUp(self):
        super(TwoStepAuthProfileHotpTestCase, self).setUp()
        self.user_otp = User.objects.get(username='test_otp')
        self.original_reuse_setting = ts_settings.TWOSTEPAUTH_DISALLOW_REUSE
        ts_settings.TWOSTEPAUTH_DISALLOW_REUSE = True
        self.original_totp_setting = ts_settings.TWOSTEPAUTH_TOTP
        ts_settings.TWOSTEPAUTH_TOTP = False

    def tearDown(self):
        super(TwoStepAuthProfileHotpTestCase, self).tearDown()
        ts_settings.TWOSTEPAUTH_DISALLOW_REUSE = self.original_reuse_setting
        ts_settings.TWOSTEPAUTH_TOTP = self.original_totp_setting

    def test_validate_hotp(self):
        """ Profile : Validate HOTP """
        s = self.user_otp.get_profile()
        method = 'APP'
        code = hotp_data[0][1]
        self.assertTrue(s.validate(code, method))
