#!/bin/bash -e
# Copyright (C) 2010-2014 Immunity Inc.
# This file is part of El Jefe - http://www.immunityinc.com/products-eljefe.shtml
# See the file 'docs/LICENSE' for copying permission.

MACHINE_TYPE=`uname -m`

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

echo "Checking architecture ..."
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
  REPO_URL="baseurl=http://downloads-distro.mongodb.org/repo/redhat/os/x86_64/"
else
  REPO_URL="baseurl=http://downloads-distro.mongodb.org/repo/redhat/os/i686/"
fi

echo "Adding MongoDB repository ..."
touch /etc/yum.repos.d/mongodb.repo
echo "[mongodb]" >> /etc/yum.repos.d/mongodb.repo
echo "name=MongoDB Repository" >> /etc/yum.repos.d/mongodb.repo
echo  $REPO_URL >> /etc/yum.repos.d/mongodb.repo
echo "gpgcheck=0" >> /etc/yum.repos.d/mongodb.repo
echo "enabled=1" >> /etc/yum.repos.d/mongodb.repo


echo "Installing El Jefe dependencies ..."
easy_install pip
yum -y install python-psycopg2 postgres postgresql-server mongo-10gen mongo-10gen-server python-devel gcc gcc-c++ make openssl-devel
pip install django==1.6 django-taggit requests numpy pymongo pycrypto jinja2 sqlalchemy bson django-bootstrap3

echo 'Configuring Postgresql'

service postgresql initdb
chkconfig postgresql on
service postgresql start

echo "Creating Postgresql tables and user ..."

sudo -u postgres psql postgres -c "CREATE USER admin with password 'admin'"
sudo -u postgres psql postgres -c "CREATE DATABASE eljefe OWNER admin"
sudo -u postgres psql postgres -c "CREATE DATABASE cuckoo OWNER admin"


echo "Changing Postgres auth for 127.0.0.1 connections ..."
sed -i '/host    all             all             127.0.0.1\/32/ s/ident/md5/' /var/lib/pgsql/data/pg_hba.conf

echo "Restarting Postgres ..."
service postgresql restart

echo "Creating tables ..."
cd webapp
python manage.py syncdb

echo "Add the corresponding rules for iptables to allow incoming connection for postgresql (default port 5432) and ElJefeXMLServer (default port 5555)."

echo "All done."

