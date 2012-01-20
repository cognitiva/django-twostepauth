#coding: utf-8
import base64
import hashlib
import hmac
import logging
import struct
from time import time as now
from django.db import models
from django.utils.translation import ugettext_lazy as _
from .utils import generate_secret, generate_backup_codes
from . import settings as twostepauth_settings


class TwoStepAuthBaseProfile(models.Model):
    tsa_active = models.BooleanField(_('Two-step auth active'), default=False)
    tsa_secret = models.CharField(_('TSA Secret'), max_length=100, blank=True, null=True)  # TODO should be encoded? neeeded len?
    tsa_backup_codes = models.CharField(_('TSA Backup codes'), max_length=255, blank=True, null=True)
    tsa_hotp_counter = models.PositiveIntegerField(_('TSA HOTP counter'), default=1)
    tsa_skew = models.IntegerField(_('TSA skew'), default=0)

    class Meta:
        abstract = True

    def twostep_auth_enabled(self):
        """
        Returns True if two-step authentication is enabled for users, 
        otherwise returns False
        """
        return twostepauth_settings.TWOSTEPAUTH_FOR_USERS

    def validate_totp(self, code):
        """based on http://code.google.com/p/google-authenticator/source/browse/libpam/pam_google_authenticator.c
        function check_timebased_code

        and, for the math:
        http://www.brool.com/index.php/using-google-authenticator-for-your-website

        Returns:
            False - invalid code
            True - valid code
        """
        try:
            code = int(code)
        except TypeError:
            return False
        if code < 0 or code >= 1000000:
            # All time based verification codes are no longer than six digits.
            raise False
        # Compute verification codes and compare them with user input
        tm = int(now() / twostepauth_settings.TWOSTEPAUTH_TIME_STEP_SIZE)

        for i in range(-(twostepauth_settings.TWOSTEPAUTH_TOTP_WINDOW_SIZE - 1) / 2, (twostepauth_settings.TWOSTEPAUTH_TOTP_WINDOW_SIZE + 1) / 2):
            time_interval = tm + self.tsa_skew + i
            computed_hash = self.compute_code(time_interval)
            if computed_hash == code:
                return self.invalidate_totp_code(time_interval)
        if twostepauth_settings.TWOSTEPAUTH_AJDUST_SKEW:
            #The most common failure mode is for the clocks to be insufficiently
            #synchronized. We can detect this and store a skew value for future
            #use.
            skew = None
            for i in range(twostepauth_settings.TWOSTEPAUTH_SKEW_ADJUST_WINDOW):
                computed_hash = self.compute_code(tm - i)
                if computed_hash == code and skew is None:
                    #Don't short-circuit out of the loop as the obvious difference in
                    #computation time could be a signal that is valuable to an attacker.
                    skew = -i
                computed_hash = self.compute_code(tm + i)
                if computed_hash == code and skew is None:
                    skew = i
            if skew is not None:
                return self.check_time_skew(tm, skew)
        return False

    def validate_hotp(self, code):
        """
        Verifies HOTP code and updates the hotp_counter field. Saves the
        object.

         Returns:
            False - invalid code
            True - valid code
        """
        try:
            code = int(code)
        except TypeError:
            return False
        if code < 0 or code >= 1000000:
            return False
        if self.tsa_hotp_counter < 1:
            # missing counter for current user in our database
            return False
        for i in range(twostepauth_settings.TWOSTEPAUTH_HOTP_WINDOW_SIZE):
            computed_hash = self.compute_code(self.tsa_hotp_counter + i)
            if (computed_hash == code):
                #advance counter to following step
                self.tsa_hotp_counter += i + 1
                self.save()
                return True
        #We must advance the counter for each hotp login attempt
        self.tsa_hotp_counter += 1
        self.save()
        return False

    def validate(self, code, method):
        if method == 'APP':
            if twostepauth_settings.TWOSTEPAUTH_TOTP:
                return self.validate_totp(code)
            else:
                return self.validate_hotp(code)
        elif method == 'BACKUP':
            try:
                try:
                    icode = int(code)
                except TypeError:
                    return False
                backup_codes = self.get_backup_codes()
                if icode in backup_codes:
                    #remove from the backup list so that it can only be used once
                    backup_codes.remove(icode)
                    self.set_backup_codes(backup_codes)
                    self.save()
                    return True
                else:
                    return False
            except ValueError:
                return False

    def compute_code(self, tm):
        b = struct.pack(">Q", tm)  # unsigned long long?
        secret = base64.b32decode(self.tsa_secret)
        hm = hmac.new(secret, b, hashlib.sha1).digest()
        offset = ord(hm[-1]) & 0x0F
        truncatedHash = struct.unpack(">I", hm[offset:offset + 4])[0]  # unsigned int
        truncatedHash &= 0x7FFFFFFF
        truncatedHash %= 1000000
        return truncatedHash

    def get_backup_codes(self):
        """
        Returns the backup codes from the model as a list of values. Internally the 
        backup codes are stored as a string of semicolon separated values.
        """
        if self.tsa_backup_codes:
            return map(int, self.tsa_backup_codes.split(';'))
        else:
            return []

    def set_backup_codes(self, codes):
        """
        Stores the backup codes in the model as a string of semicolon separated values
        """
        self.tsa_backup_codes = ";".join(map(str, codes))

    def invalidate_totp_code(self, tm):
        """If the TWOSTEPAUTH_DISALLOW_REUSE option has been set, record the timestamps that have been
           used to log in successfully and disallow their reuse.

        Returns:
             True - the timestamp is allowed
             False - the timestamp is already blocked
        """
        if not twostepauth_settings.TWOSTEPAUTH_DISALLOW_REUSE:
            return True
        blocked_ts = self.user.blockedtimestamp_set.filter(timestamp=tm)
        if blocked_ts:
            #FIXME better log or show to the user?
            logger = logging.getLogger(__name__)
            logger.error("Trying to reuse a previously used time-based code. "
                  "Retry again in 30 seconds. "
                  "Warning! This might mean, you are currently subject to a "
                  "man-in-the-middle attack.")
            return False
        #If the blocked code is outside of the possible window of timestamps, remove it.
        q1 = models.Q(timestamp__lte=tm - twostepauth_settings.TWOSTEPAUTH_TOTP_WINDOW_SIZE)
        q2 = models.Q(timestamp__gte=twostepauth_settings.TWOSTEPAUTH_TOTP_WINDOW_SIZE + tm)
        purge_ts = self.user.blockedtimestamp_set.filter(q1 | q2)
        purge_ts.delete()

        # Add timestamp to the blacklist
        self.user.blockedtimestamp_set.create(timestamp=tm)
        return True

    def check_time_skew(self, tm, skew):
        """
        If the user enters a sequence of TWOSTEPAUTH_RESETTING_SKEW_SEQUENCE codes that are valid
        for within RESETTING_SKEW_WINDOW of the current time, and he does it in quick succession,
        we assume that he's the legitimate user but there's a mismatch between the code
        generator clock and the system clock, so skew is adjusted.
        """
        resetting_list = list(self.user.totp_skew_set.all()[:twostepauth_settings.TWOSTEPAUTH_RESETTING_SKEW_SEQUENCE - 1])
        if resetting_list:
            # If the user entered an identical code, assume they are just getting
            # desperate. This doesn't actually provide us with any useful data,
            # though. Don't change any state and hope the user keeps trying a few
            # more times.
            if (tm, skew) == (resetting_list[0].timestamp, resetting_list[0].skew):
                return None
        new_rts = ResettingTimeSkew(user=self.user, timestamp=tm, skew=skew)
        resetting_list.insert(0, new_rts)
        # Check if we have the required amount of valid entries.
        if len(resetting_list) == twostepauth_settings.TWOSTEPAUTH_RESETTING_SKEW_SEQUENCE:
            #Check that we have a consecutive sequence of timestamps with no big
            #gaps in between. Also check that the time skew stays constant. Allow
            #a minor amount of fuzziness on all parameters.
            if not filter(
                lambda (tm1, tm0): tm1.timestamp <= tm0.timestamp or tm1.timestamp > tm0.timestamp + 2 or
                    tm0.skew - tm1.skew < -1 or tm0.skew - tm1.skew > 1,
                zip(resetting_list[:-1], resetting_list[1:])):
                    # The user entered the required number of valid codes in quick
                    # succession. Establish a new valid time skew for all future login
                    # attempts.
                    avg_skew = sum([tm.skew for tm in resetting_list]) / twostepauth_settings.TWOSTEPAUTH_RESETTING_SKEW_SEQUENCE
                    self.tsa_skew = avg_skew
                    self.save()
                    self.user.totp_skew_set.all().delete()
                    return True
        new_rts.save()
        self.user.totp_skew_set.filter(timestamp__lt=resetting_list[-1].timestamp).delete()
        return False

    def save(self):
        if self.tsa_active:
            if not self.tsa_secret:
                self.tsa_secret = generate_secret()
            if not self.tsa_backup_codes:
                self.set_backup_codes(generate_backup_codes())
        super(TwoStepAuthBaseProfile, self).save()

    def __unicode__(self):
        return unicode(self.user)


class BlockedTimestamp(models.Model):
    user = models.ForeignKey("auth.User")
    timestamp = models.PositiveIntegerField()

    def __unicode__(self):
        return u"%s, %u" % (unicode(self.user), self.timestamp)


class ResettingTimeSkew(models.Model):
    user = models.ForeignKey("auth.User", related_name="totp_skew_set")
    timestamp = models.PositiveIntegerField()
    skew = models.IntegerField()

    def __unicode__(self):
        return u"%s, %u%+d" % (unicode(self.user), self.timestamp, self.tsa_skew)

    class Meta:
        ordering = ['-timestamp']
