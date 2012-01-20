import os
import urlparse
from django.conf import settings
from django.contrib.auth import SESSION_KEY
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.core.urlresolvers import reverse
#from django.test import TestCase

from .base import TwoStepAuthProfileTestCaseBase, otp_data, get_fake_time_fn
from .. import models
from ..forms import TokenAuthenticationForm

class TwoStepAuthenticationViewsTestCase(TwoStepAuthProfileTestCaseBase):
    """
    Helper base class for all the follow test cases.
    """
    fixtures = ['test_users.json', ]
    urls = 'twostepauth.tests.urls'

    def setUp(self):
        super(TwoStepAuthenticationViewsTestCase, self).setUp()
        self.old_now = models.now
        models.now = get_fake_time_fn()
        self.old_TEMPLATE_DIRS = settings.TEMPLATE_DIRS
        settings.TEMPLATE_DIRS = (
            os.path.join(os.path.dirname(__file__), 'templates'),
            os.path.join(os.path.dirname(__file__), os.pardir, 'templates'),
        )
        self.old_TEMPLATE_LOADERS = settings.TEMPLATE_LOADERS
        settings.TEMPLATE_LOADERS = ('django.template.loaders.filesystem.Loader',)
 

    def tearDown(self):
        settings.TEMPLATE_LOADERS = self.old_TEMPLATE_LOADERS
        settings.TEMPLATE_DIRS = self.old_TEMPLATE_DIRS
        models.now = self.old_now
        super(TwoStepAuthenticationViewsTestCase, self).tearDown()

    def login(self, username='username', password='password'):
        response = self.client.post(reverse('auth_login'), {
            'username': username,
            'password': password
            }
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response['Location'].endswith(settings.LOGIN_REDIRECT_URL))
        self.assertTrue(SESSION_KEY in self.client.session)

    def step_one(self, username='username', password='password'):
        response = self.client.post(reverse('auth_login'), {
            'username': username,
            'password': password
            }
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(isinstance(response.context['form'], TokenAuthenticationForm))
        return response.context['form']

    def step_two(self, password='password'):
        response = self.client.post('/login/', {
            'username': 'testclient',
            'password': password
            }
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response['Location'].endswith(settings.LOGIN_REDIRECT_URL))
        self.assertTrue(SESSION_KEY in self.client.session)


class TestTwoStepProfile(TwoStepAuthenticationViewsTestCase):
    def test_profile_view(self):
        """
        Test the Two-Step Auth profile.

        You should be able to activate/deacivate two-step auth from that view.
        """
        self.login('test_no_otp', 'test_no_otp')
        profile_url = reverse('twostepauth_profile')
        response = self.client.get(profile_url)
        self.assertEqual(response.status_code, 200)
        # Test it's off
        self.assertFalse(response.context['profile'].tsa_active)
        # change to on
        response = self.client.post(profile_url, {"tsa_active": "checked"})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response['Location'].endswith(profile_url))
        # test that it's on, secret, codes, counter, skew are ok
        response = self.client.get(profile_url)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['profile'].tsa_active)


class TestLoginStepOne(TwoStepAuthenticationViewsTestCase):
    def test_two_step_off(self):
        """ Test that a user without tsa active is logged in after the first step. """
        self.login('test_no_otp', 'test_no_otp')

    def test_two_step_on(self):
        """ Test that a user wit tsa active is show the token form. """
        response = self.client.post(reverse('auth_login'), {
            'username': 'test_otp',
            'password': 'test_otp'
            }
        )
        self.assertEqual(response.status_code, 302)
        step_two_url = reverse('login_step_two')
        parsedurl = urlparse.urlparse(response['Location'])
        self.assertEqual(parsedurl.path, step_two_url)

    def test_invalid_credentials(self):
        """ Wrong username and password. """
        response = self.client.post(reverse('auth_login'), {
            'username': 'test_otp',
            'password': 'wrongpassword'
            }
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['form'].errors)
        response = self.client.post(reverse('auth_login'), {
            'username': 'invalid_user',
            'password': 'test_otp'
            }
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['form'].errors)


class TestLoginStepTwo(TwoStepAuthenticationViewsTestCase):
    username = 'test_otp'
    password = 'test_otp'

    def test_valid_backup_code(self):
        """ Test thet a user can login with a backup code. """
        # FIXME I really wanted to get the key from the form, but I don't know how
        # anyway, I'm only testing view #2, so it's probably ok like this.
        #f = self.step_one(username=self.username, password=self.password)
        ak = default_token_generator.make_token(User.objects.get(username=self.username))
        response = self.client.post(reverse('login_step_two'), {
                'code': '92275470',
                'method': 'BACKUP',
                'authkey': ak,
                'username': self.username
            }
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response['Location'].endswith(settings.LOGIN_REDIRECT_URL))

    def test_valid_code(self):
        """ Test thet a user can login with a code. """
        ak = default_token_generator.make_token(User.objects.get(username=self.username))
        response = self.client.post(reverse('login_step_two'), {
                'code': otp_data[0][1],
                'method': 'APP',
                'authkey': ak,
                'username': self.username
            }
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response['Location'].endswith(settings.LOGIN_REDIRECT_URL))

    def test_invalid_code(self):
        """ Test thet a user can login with a code. """
        ak = default_token_generator.make_token(User.objects.get(username=self.username))
        response = self.client.post(reverse('login_step_two'), {
                'code': '123456',
                'method': 'APP',
                'authkey': ak,
                'username': self.username
            }
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['form'].errors)

    def test_remember_computer(self):
        """ Test that the remember computer cookie is set """
        ak = default_token_generator.make_token(User.objects.get(username=self.username))
        response = self.client.post(reverse('login_step_two'), {
                'code': otp_data[0][1],
                'method': 'APP',
                'authkey': ak,
                'username': self.username,
                'remember_computer': 'checked'
            }
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.cookies.has_key('_auth_2step_user_id'))


