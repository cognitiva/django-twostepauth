from django.conf import settings

# Use T(ime-based)OTP. Set to False to use H(mac-based) OTP
TWOSTEPAUTH_TOTP = getattr(settings, 'TWOSTEPAUTH_TOTP', True)

#record timestamps have been used to log in successfully and disallow their reuse.
TWOSTEPAUTH_DISALLOW_REUSE = getattr(settings, 'TWOSTEPAUTH_DISALLOW_REUSE', True)

#FIXME - can we have both at the same time or can we have just 1 window_size setting?
# Window size for counter-based validation
TWOSTEPAUTH_HOTP_WINDOW_SIZE = getattr(settings, 'TWOSTEPAUTH_HOTP_WINDOW_SIZE', 3)

# Window size for time-based validation
TWOSTEPAUTH_TOTP_WINDOW_SIZE = getattr(settings, 'TWOSTEPAUTH_TOTP_WINDOW_SIZE', 10)

# Time-step size in seconds for time-based validation
TWOSTEPAUTH_TIME_STEP_SIZE = getattr(settings, 'TWOSTEPAUTH_TIME_STEP_SIZE', 30)

# Try to compensate for desynchronized clocks
TWOSTEPAUTH_AJDUST_SKEW = getattr(settings, 'TWOSTEPAUTH_AJDUST_SKEW', True)

# number of sequential timestamps the user must enter for the skew to be adjusted
TWOSTEPAUTH_RESETTING_SKEW_SEQUENCE = getattr(settings, 'TWOSTEPAUTH_RESETTING_SKEW_SEQUENCE', 3)  # because google says so :-P

# when adjusting the skew parameter, the number of intervals we search for a matching code before and after the current time
TWOSTEPAUTH_SKEW_ADJUST_WINDOW = getattr(settings, 'TWOSTEPAUTH_SKEW_ADJUST_WINDOW', 25 * 60)

#Activate two step authentication for the site
TWOSTEPAUTH_FOR_USERS = getattr(settings, 'TWOSTEPAUTH_FOR_USERS', False)

#Activate two step authentication for the admin section of the site
TWOSTEPAUTH_FOR_ADMIN = getattr(settings, 'TWOSTEPAUTH_FOR_ADMIN', False)

#Configure the number of days before a computer/browser asks again the token
TWOSTEPAUTH_REMEMBER_COMPUTER_DAYS = getattr(settings,
                                        'TWOSTEPAUTH_REMEMBER_COMPUTER_DAYS',
                                        30)

#session identifier for two step auth login 
TWOSTEPAUTH_SESSION_KEY = getattr(settings, 'TWOSTEPAUTH_SESSION_KEY', '_auth_2step_user_id')