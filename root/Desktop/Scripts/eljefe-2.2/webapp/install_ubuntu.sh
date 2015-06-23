#!/bin/bash -e
# Copyright (C) 2010-2014 Immunity Inc.
# This file is part of El Jefe - http://www.immunityinc.com/products-eljefe.shtml
# See the file 'docs/LICENSE' for copying permission.

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

echo "Installing El Jefe dependencies ..."

apt-get -y install python-psycopg2 build-essential python-dev python-pip postgresql mongodb python-sqlalchemy python-bson python-dpkt python-jinja2 python-magic python-bottle python-pefile python-chardet

pip install django==1.6 django-taggit django-bootstrap3 requests numpy pymongo pycrypto

echo "Creating Postgresql tables and user ..."

sudo -u postgres psql postgres -c "CREATE USER admin with password 'admin'"
sudo -u postgres psql postgres -c "CREATE DATABASE eljefe OWNER admin"
sudo -u postgres psql postgres -c "CREATE DATABASE cuckoo OWNER admin"

echo "Restarting Postgres ..."

/etc/init.d/postgresql restart

echo "Creating tables ..."

python manage.py syncdb

echo "All done."
