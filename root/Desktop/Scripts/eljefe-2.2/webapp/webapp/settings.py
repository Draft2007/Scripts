# Django settings for webapp project.
import os.path

import sys
import os


PROJECT_ROOT = os.path.dirname(os.path.realpath(__file__))
HOMEDIR = os.path.split(PROJECT_ROOT)[0]

CAMAL_APIKEY = '6534019742b23af465bd907fe7249cf617adf95541f2fc0fc75d0423e495ae3f'
CUCKOO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                           "..", 
                           "..", 
                           'cuckoo')

CUCKOO_FOUND = os.path.exists(CUCKOO_PATH)

DEBUG = True
TEMPLATE_DEBUG = DEBUG
# Use this with debug false
#ALLOWED_HOSTS = ['eljefe.demo.immunityinc.com']


ADMINS = (('admin','admin@immunityinc.com'),
    # ('Your Name', 'your_email@domain.com'),
)

MANAGERS = ADMINS

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2', # Add 'postgresql_psycopg2', 'postgresql', 'mysql', 'sqlite3' or 'oracle'.
        'NAME': 'eljefe',                      # Or path to database file if using sqlite3.
        'USER': 'admin',                      # Not used with sqlite3.
        'PASSWORD': 'admin',                  # Not used with sqlite3.
        'HOST': '127.0.0.1',                      # Set to empty string for localhost. Not used with sqlite3.
        'PORT': '5432',                      # Set to empty string for default. Not used with sqlite3.
    }
}
# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# If running in a Windows environment this must be set to the same as your
# system time zone.
#TIME_ZONE = 'America/Chicago'
TIME_ZONE = None
#USE_TZ = True

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-us'

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# Absolute path to the directory that holds media.
# Example: "/home/media/media.lawrence.com/"
MEDIA_ROOT = HOMEDIR + '/home/imedia'

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash if there is a path component (optional in other cases).
# Examples: "http://media.lawrence.com", "http://example.com/media/"
MEDIA_URL = '/imedia/'

STATIC_URL = '/static/'

# URL prefix for admin media -- CSS, JavaScript and images. Make sure to use a
# trailing slash.
# Examples: "http://foo.com/media/", "/media/".
ADMIN_MEDIA_PREFIX = '/media/'

# Make this unique, and don't share it with anybody.
SECRET_KEY = '5ktp*foax+nivlnll98uru92u6)s=^v*b0dcm)vlyi)8bl&2z('

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
#     'django.template.loaders.eggs.load_template_source',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
)

ROOT_URLCONF = 'webapp.urls'

TEMPLATE_DIRS = (
    # Put strings here, like "/home/html/django_templates" or "C:/www/django/templates".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
    HOMEDIR + "/templates"
)

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.admin',
    'django.contrib.comments',
    'django.contrib.staticfiles',
    'bootstrap3',
    'home',
    #'south',
    'taggit',
    'analysis',
    'bootstrap3',
    'alerts',
    #'debug_toolbar'
)


SESSION_ENGINE = 'django.contrib.sessions.backends.file'

if CUCKOO_FOUND:
    
    sys.path.append(CUCKOO_PATH)
    
    from lib.cuckoo.common.constants import CUCKOO_ROOT
    from lib.cuckoo.common.config import Config
    
    cfg = Config(cfg=os.path.join(CUCKOO_PATH,"conf", "reporting.conf")).mongodb
    
    # Checks if mongo reporting is enabled in Cuckoo.
    if not cfg.get("enabled"):
        raise Exception("Mongo reporting module is not enabled in cuckoo, aborting!")
    
    # Get connection options from reporting.conf.
    MONGO_HOST = cfg.get("host", "127.0.0.1")
    MONGO_PORT = cfg.get("port", 27017)
