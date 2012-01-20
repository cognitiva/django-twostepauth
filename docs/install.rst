============
Installation
============

Package installation
--------------------

Steps for installation for ``django-twostepauth``.

Pre-requisites: 
	
	Python 2.5 or greater
    Django 1.3 or greater

To install it, run the following command inside this directory::

    python setup.py install

If you have the Python ``easy_install`` utility available, you can
also type the following to download and install in one step::

   easy_install -Z django-twostepauth

(the ``-Z`` flag is required to force ``easy_install`` to do a normal
source install rather than a zipped egg)

Or if you're using ``pip``::

    pip install django-twostepauth

Or if you'd prefer you can simply place the included ``twostepauth``
directory somewhere on your Python path, or symlink to it from
somewhere on your Python path.

Package configuration
---------------------

Add the ``twostepauth`` package to the list of ``INSTALLED_APPS``.

The ``AUTHENTICATION_BACKENDS`` must set as the authentication backend the 
supplied backend ``twostepauth.auth_backend.TwoStepAuthBackend``. It 
important that the standard backend is not kept in the sequence of 
backends as this would authenticate the users before the second step.

To allow the two-step authentication for users set ``TWOSTEPAUTH_FOR_USERS`` 
to True. To activate two-step authentication for the admin section of
the site set ``TWOSTEPAUTH_FOR_ADMIN`` to True.

Two-step authentication needs to store extra information for each user. This is kept 
in the user profile, so you'll need to create a profile model that inherits from
``twostepauth.models.TwoStepAuthBaseProfile``:

    from twostepauth.models import TwoStepAuthBaseProfile

    class UserProfile(TwoStepAuthBaseProfile):
        user = models.OneToOneField('auth.User')

and in ``settings.py`` indicate that this model is the user profile model:

    AUTH_PROFILE_MODULE = 'myapp.UserProfile'


In the urls configuration set the two-step login views 

    url(r'^accounts/login/$', 
        'twostepauth.views.login_step_one', 
        name='auth_login'),
    url(r'^accounts/login/step_two$', 
        'twostepauth.views.login_step_two', 
        name='login_step_two')

The ``twostepauth`` also includes a view for the user profile management of
the two-step authentication. Example setup for this view:

    url(r'^profiles/twostepauth/$', 
        'twostepauth.views.twostepauth_profile', 
        name='twostepauth_profile'),

You will need to create a template named ``twostepauth/profile.html``. You can
find an example in the ``exampleapp`` application included in this distribution.


Demo Application
----------------

The demo application is an setup example of authentication, registration and profile 
using the ``django-registration`` and ``django-profiles`` packages.

To try the demo application install the above packages (note that django-registration
must be version 0.8 alpha or above).

	pip install https://bitbucket.org/ubernostrum/django-registration/downloads/django-registration-0.8-alpha-1.tar.gz

    pip install django-profiles




Management Command
------------------

The Django management command ``generate_twostepauth_secret`` can be used to activate two-step
authentication for a user and generate the secret key from the command line:

    python manage.py generate_twostepauth_secret <username>
