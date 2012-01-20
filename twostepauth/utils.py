#coding: utf-8
import base64
import random
from datetime import date
from urllib import urlencode
from django.utils.http import int_to_base36, base36_to_int
from django.utils.crypto import constant_time_compare, salted_hmac
from twostepauth import settings as twostepauth_settings

def generate_secret():
    """
    Creates a new secret code to be used in the setup of Google Authenticator
    or similar token devices. 
    """
    SECRET_BYTES = 10  #size for Google Authenticator App
    buf = [chr(random.randint(0,255)) for x in range(SECRET_BYTES)]
    bufstr = "".join(buf)
    return base64.b32encode(bufstr)

def build_chart_url(token, username, hostname):
    """
    Build the url for the Google service to generate the QR code to setup the
    token in the mobile app.
    """
    otp_type = 't' if twostepauth_settings.TWOSTEPAUTH_TOTP else 'h'
    chl = 'otpauth://%cotp/%s@%s?secret=%s' % (otp_type, username, hostname, token)
    params = urlencode({'chs':'200x200', 'chld':'M|0', 'cht':'qr','chl':chl})
    url = 'https://chart.googleapis.com/chart?%s' % params
    return url

def generate_single_backup_code(length=8):
    """
    Backup code is a integer starting with a number between 1-9 with given length
    """
    code = [str(random.randint(1,9))] + [str(random.randint(0,9)) for x in range(length-1)]
    return "".join(code)

def generate_backup_codes(size=10):
    """
    Return a list with backup codes with the number of items from the size parameter
    """
    return [generate_single_backup_code() for i in range(size)]


class RememberComputerTokenGenerator(object):
    """
    Object to generate and check tokens used to persist the second step of the
    login process in the computer browser. Modeled after the Django 
    PasswordResetTokenGenerator.
    """
    def make_token(self, user):
        """
        Returns a token for the given user
        """
        return self._make_token(user, self._num_days(self._today()))

    def check_token(self, user, token):
        """
        Checks if the given token is valid for the given user
        """
        try:
            ts_b36, hash = token.split("-")
        except ValueError:
            return False

        try:
            ts = base36_to_int(ts_b36)
        except ValueError:
            return False

        # Check that the timestamp/uid has not been tampered with
        if not constant_time_compare(self._make_token(user, ts), token):
            return False

        if (self._num_days(self._today()) - ts) > twostepauth_settings.TWOSTEPAUTH_REMEMBER_COMPUTER_DAYS:
            return False
        return True

    def _make_token(self, user, timestamp):
        """
        Internal generation of the token based in the user and timestamp
        """
        key_salt = "RememberComputerTokenGenerator"
        ts_b36 = int_to_base36(timestamp)
        value = unicode(user.id) + unicode(timestamp)
        hash = salted_hmac(key_salt, value).hexdigest()[::2]
        return "%s-%s" % (ts_b36, hash)

    def _num_days(self, dt):
        return (dt - date(2001,1,1)).days

    def _today(self):
        return date.today()