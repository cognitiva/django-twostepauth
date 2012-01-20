#coding: utf-8
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from .. import models
from ..auth_backend import TwoStepAuthBackend
from .base import TwoStepAuthProfileTestCaseBase, otp_data, hotp_data, get_fake_time_fn

class TwoStepAuthBackendTestCase(TwoStepAuthProfileTestCaseBase):
    """
    TODO we could improve by adding some tests:
    user without active code-auth
    remember_token tests

    validate will be tested in more detail somewhere else
    """
    fixtures = ['test_users.json', ]

    def setUp(self):
        super(TwoStepAuthBackendTestCase, self).setUp()
        self.old_now = models.now
        models.now = get_fake_time_fn()
        self.backend = TwoStepAuthBackend()

    def tearDown(self):
        models.now = self.old_now
        super(TwoStepAuthBackendTestCase, self).tearDown()

    def test_user_no_profile(self):
        """Test that a user with no profile is treated as not having two-step enabled"""
        user = self.backend.authenticate(username='test_no_profile', password='test_no_profile')
        self.assertIsInstance(user, User)
        self.assertEqual(user.username, 'test_no_profile')

    def test_user_no_twostep(self):
        """Test that a user with two-step auth disabled may authenticate with username + password"""
        user = self.backend.authenticate(username='test_no_otp', password='test_no_otp')
        self.assertIsInstance(user, User)
        self.assertEqual(user.username, 'test_no_otp')

    def test_user_otp(self):
        """User with correct (username, password, code) is authenicated"""
        user = self.backend.authenticate(username='test_otp', password='test_otp', code=otp_data[0][1])
        self.assertIsInstance(user, User)
        self.assertEqual(user.username, 'test_otp')

    def test_wrong_pwd(self):
        """Wrong password must fail"""
        user = self.backend.authenticate(username='test_otp', password='wrongpassword', code=otp_data[0][1])
        self.assertIsNone(user)

    def test_wrong_otp(self):
        """User with correct (username, password) but an invalid code is not authenicated"""
        user = self.backend.authenticate(username='test_otp', password='test_otp', code='123456')
        self.assertIsNone(user)

    def test_user_otp_backup(self):
        """User with correct (username, password) and backup code is authenticated"""
        user = self.backend.authenticate(username='test_otp', password='test_otp', code=88611506, method='BACKUP')
        self.assertIsInstance(user, User)
        self.assertEqual(user.username, 'test_otp')

    def test_first_step(self):
        """Test first_step(): user with correct (username, password) and two-step auth enabled returns a token."""
        user = User.objects.get(username='test_otp')
        token = self.backend.first_step(username='test_otp', password='test_otp')
        expected = default_token_generator.make_token(user)
        self.assertEqual(token, expected)

    def test_second_step(self):
        """User with valid (username, token generated by first_step, time-based code) is authenticated."""
        user = User.objects.get(username='test_otp')
        token = self.backend.first_step(username='test_otp', password='test_otp')
        user = self.backend.authenticate(username='test_otp', token=token, code=otp_data[0][1])
        self.assertIsInstance(user, User)
        self.assertEqual(user.username, 'test_otp')

    def test_second_step_invalid_token(self):
        """User with valid (username, time-based code) but invalid token is not authenticated."""
        user = User.objects.get(username='test_otp')
        token = '33w-d9vsdv8157c84de65668'
        user = self.backend.authenticate(username='test_otp', token=token, code=otp_data[0][1])
        self.assertIsNone(user)

    def test_second_step_invalid_code(self):
        """User with valid (username, token) but invalid code is not authenticated."""
        user = User.objects.get(username='test_otp')
        token = self.backend.first_step(username='test_otp', password='test_otp')
        user = self.backend.authenticate(username='test_otp', token=token, code='123456')
        self.assertIsNone(user)

    def test_force_single_step(self):
        """Test that a user with two-step auth enabled is authenicated with (username, password) only if force_single_step is True."""
        user = self.backend.authenticate(username='test_otp', password='test_otp')
        self.assertIsNone(user)
        user = self.backend.authenticate(username='test_otp', password='test_otp', force_single_step=True)
        self.assertIsInstance(user, User)
        self.assertEqual(user.username, 'test_otp')

    def test_backup_code(self):
        """Test user with backup code."""
        user = User.objects.get(username='test_otp')
        token = self.backend.first_step(username='test_otp', password='test_otp')
        user = self.backend.authenticate(username='test_otp', token=token, method='BACKUP', code='40243962')
        self.assertIsInstance(user, User)
        self.assertEqual(user.username, 'test_otp')
