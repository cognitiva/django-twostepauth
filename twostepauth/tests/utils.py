from datetime import date, timedelta
import django.test
from django.contrib.auth.models import User
from .. import settings as ts_settings
from .. import utils

class TestBackupCodes(django.test.TestCase):
    
    def test_single_code(self):
        size = 8
        code = utils.generate_single_backup_code(size)
        self.assertEquals(len(code), size)
        self.assertIn(int(code[0]), [1,2,3,4,5,6,7,8,9] )

    def test_list_codes(self):
        codes = utils.generate_backup_codes(size=10)
        self.assertEquals(len(codes), 10)


class TestRememberComputerTokenGenerator(django.test.TestCase):
    
    def test_make_token(self):
        user = User.objects.create_user('u1', 'u1@example.com', 'secret')
        tg = utils.RememberComputerTokenGenerator()
        token = tg.make_token(user)
        self.assertTrue(tg.check_token(user, token))
    
    def test_timeout(self):
        class Mocked(utils.RememberComputerTokenGenerator):
            def __init__(self, today):
                self._today_val = today
            def _today(self):
                return self._today_val
        user = User.objects.create_user('u1', 'u1@example.com', 'secret')
        tg = utils.RememberComputerTokenGenerator()
        token = tg.make_token(user)
        mocked_gen = Mocked(date.today() + timedelta(ts_settings.TWOSTEPAUTH_REMEMBER_COMPUTER_DAYS))
        self.assertTrue(mocked_gen.check_token(user, token))
        mocked_gen2 = Mocked(date.today() + timedelta(ts_settings.TWOSTEPAUTH_REMEMBER_COMPUTER_DAYS + 1))
        self.assertFalse(mocked_gen2.check_token(user, token))
        