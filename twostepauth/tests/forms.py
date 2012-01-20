import django.test
from django.db import models
from django.contrib.auth.models import User
from ..forms import TwoStepAuthenticationForm, TokenAuthenticationForm, \
          SingleStepAdminAuthenticationForm, TwoStepAdminAuthenticationForm
from .. import settings as ts_settings
from base import TwoStepAuthProfileTestCaseBase


class TestTwoStepAuthenticationFormBase(TwoStepAuthProfileTestCaseBase):
    def _create_user(self, username, email, password):
        profile_model = models.get_model('twostepauth', 'TestProfile')
        u = User.objects.create_user('u1','u1@example.com','secret')
        p = profile_model(user=u)
        p.save()
        return u

    def setUp(self):
        super(TestTwoStepAuthenticationFormBase, self).setUp()
        #user with two-step active and staff
        self.u1 = self._create_user('u1','u1@example.com','secret')
        self.u1.is_staff = True
        self.u1.save()
        p1 = self.u1.get_profile()
        p1.tsa_active = True
        p1.save()
        #user with two-step inactive and non staff
        self.u2 = User.objects.create_user('u2','u2@example.com','secret')
        #inactive user
        self.u3 = User.objects.create_user('u3','u3@example.com','secret')
        self.u3.is_active = False
        self.u3.save()
        #user with two-step inactive and staff
        self.u4 = User.objects.create_user('u4','u4@example.com','secret')
        self.u4.is_staff = True
        self.u4.save()


class TestTwoStepAuthenticationForm(TestTwoStepAuthenticationFormBase):
    def test_site_active(self):
        old_set = ts_settings.TWOSTEPAUTH_FOR_USERS
        ts_settings.TWOSTEPAUTH_FOR_USERS = True
        form = TwoStepAuthenticationForm(data={'username':'u1', 'password':'secret'})
        self.failUnless(form.is_valid())
        self.assertIsNone(form.user)
        form = TwoStepAuthenticationForm(data={'username':'u1', 'password':'foo'})
        self.failIf(form.is_valid())
        form = TwoStepAuthenticationForm(data={'username':'u2', 'password':'secret'})
        self.failUnless(form.is_valid())
        self.assertIsNotNone(form.user)
        #user is inactive
        form = TwoStepAuthenticationForm(data={'username':self.u3.username, 
                                               'password':'secret'})
        self.failIf(form.is_valid())
        ts_settings.TWOSTEPAUTH_FOR_USERS = old_set
    
    def test_site_inactive(self):
        old_set = ts_settings.TWOSTEPAUTH_FOR_USERS
        ts_settings.TWOSTEPAUTH_FOR_USERS = False
        form = TwoStepAuthenticationForm(data={'username':'u1', 'password':'secret'})
        self.failUnless(form.is_valid())
        self.assertIsNotNone(form.user)
        form = TwoStepAuthenticationForm(data={'username':'u1', 'password':'foo'})
        self.failIf(form.is_valid())
        form = TwoStepAuthenticationForm(data={'username':'u2', 'password':'secret'})
        self.failUnless(form.is_valid())
        self.assertIsNotNone(form.user)
        ts_settings.TWOSTEPAUTH_FOR_USERS = old_set


class TestTokenAuthenticationForm(TestTwoStepAuthenticationFormBase):
    def test_step_two(self):
        form1 = TwoStepAuthenticationForm(data={'username':self.u1.username, 
                                                'password':'secret'})
        form1.is_valid()
        self.failUnless(form1.is_valid())
        self.assertIsNotNone(form1.usertoken)
        #invalid
        form2 = TokenAuthenticationForm(data={'code':'0', 'method':'APP', 
                    'authkey': form1.usertoken, 'username':self.u1.username})
        self.failIf(form2.is_valid())
        form2 = TokenAuthenticationForm(data={'code':'9999999', 'method':'APP', 
                    'authkey': form1.usertoken, 'username':self.u1.username})
        self.failIf(form2.is_valid())
        code = self.u1.get_profile().get_backup_codes()[0]
        form2 = TokenAuthenticationForm(data={'code':code, 'method':'BACKUP', 
                    'authkey': 'wrongkey', 'username':self.u1.username})
        self.failIf(form2.is_valid())
        #valid
        code = self.u1.get_profile().get_backup_codes()[0]
        form2 = TokenAuthenticationForm(data={'code':code, 'method':'BACKUP', 
                    'authkey': form1.usertoken, 'username':self.u1.username})
        self.failUnless(form2.is_valid())


class TestSingleStepAdminAuthenticationForm(TestTwoStepAuthenticationFormBase):
    def setUp(self):
        super(TestSingleStepAdminAuthenticationForm, self).setUp()
        self.old_set = ts_settings.TWOSTEPAUTH_FOR_ADMIN
        ts_settings.TWOSTEPAUTH_FOR_ADMIN = False
    
    def tearDown(self):
        super(TestSingleStepAdminAuthenticationForm, self).tearDown()
        ts_settings.TWOSTEPAUTH_FOR_ADMIN = self.old_set
    
    def test_success(self):
        form = SingleStepAdminAuthenticationForm(data={'username':self.u1.username,
                                                       'password':'secret',
                                                       'this_is_the_login_form':1})
        self.failUnless(form.is_valid())

    def test_fail_invalid_pass(self):
        form = SingleStepAdminAuthenticationForm(data={'username':self.u1.username,
                                                       'password':'foo',
                                                       'this_is_the_login_form':1})
        self.failIf(form.is_valid())
    
    def test_fail_inactive_user(self):
        form = SingleStepAdminAuthenticationForm(data={'username':self.u3.username,
                                                       'password':'secret',
                                                       'this_is_the_login_form':1})              
        self.failIf(form.is_valid())
    
    def test_fail_not_staff(self):
        form = SingleStepAdminAuthenticationForm(data={'username':self.u2.username,
                                                       'password':'secret',
                                                       'this_is_the_login_form':1})
        self.failIf(form.is_valid())
    
    def test_fail_not_valid_username(self):
        form = SingleStepAdminAuthenticationForm(data={'username':'dummy_data',
                                                       'password':'secret',
                                                       'this_is_the_login_form':1})
        self.failIf(form.is_valid())


class TestTwoStepAdminAuthenticationForm(TestTwoStepAuthenticationFormBase):
    def setUp(self):
        super(TestTwoStepAdminAuthenticationForm, self).setUp()
        self.old_set = ts_settings.TWOSTEPAUTH_FOR_ADMIN
        ts_settings.TWOSTEPAUTH_FOR_ADMIN = True
    
    def tearDown(self):
        super(TestTwoStepAdminAuthenticationForm, self).tearDown()
        ts_settings.TWOSTEPAUTH_FOR_ADMIN = self.old_set
        
    def test_success(self):
        data = {'username': self.u4.username, 'password':'secret', 'this_is_the_login_form':1,
                'method':'APP', 'code':0}
        form = TwoStepAdminAuthenticationForm(data=data)
        self.failUnless(form.is_valid())
    
    def test_fail_needs_token(self):
        data = {'username': self.u1.username, 'password':'secret', 'this_is_the_login_form':1,
                'method':'APP', 'code':0}
        form = TwoStepAdminAuthenticationForm(data=data)
        self.failIf(form.is_valid())
    
    def test_fail_non_staff_user(self):
        data = {'username': self.u2.username, 'password':'secret', 'this_is_the_login_form':1,
                'method':'APP', 'code':0}
        form = TwoStepAdminAuthenticationForm(data=data)
        self.failIf(form.is_valid())
    
    def test_fail_wrong_pass(self):
        data = {'username': self.u4.username, 'password':'foo', 'this_is_the_login_form':1,
                'method':'APP', 'code':0}
        form = TwoStepAdminAuthenticationForm(data=data)
        self.failIf(form.is_valid())
