# Copyright (C) 2010-2014 Immunity Inc.
# This file is part of El Jefe - http://www.immunityinc.com/products-eljefe.shtml
# See the file 'docs/LICENSE' for copying permission.

import os
import datetime
import time
import sys
import math
import ssl
import hashlib 
import email
import smtplib
from email.mime.text import MIMEText
from django.core.mail import send_mail
import ntpath
from django.core.exceptions import ObjectDoesNotExist
import logging
from privs import privilegesdict

#import settings values
from settings import *

#activate logging file
logging.basicConfig(filename=LOGGING_FILENAME,
                    level=logging.INFO,
                    )

# need to find django.settings , always
if "." not in sys.path: sys.path.append(".")
if "../" not in sys.path: sys.path.append("../")
if "../../" not in sys.path: sys.path.append("../../")

# Set django settings
os.environ["DJANGO_SETTINGS_MODULE"] = "webapp.settings"

from home.models import *
from home.ssl_utils import *
import alerts.models as mAlert

#ElJefe imports
import ElJefeUtils, os, sys

# check if the received user/pass combo is valid
def checkXMLUser(user,passw):
    exists = xmlusers.objects.filter(username=user,password=passw)
    if exists:
        return True
    else:
        return False


class uppriv_database():
    Actions = {}
    def __init__(self):

        self.station_id       = None # <
        self.binary_id        = None  # <
        self.parent_binary_id = None # <
        self.process_data     = None
        self.remote_host      = None
        self.certificate      = None
        self.log_date         = None
        self.setupActions()

    def configure(self, data, remote_host, certificate, log_date = None):
        self.station_id       = None # <
        self.binary_id        = None  # <
        self.parent_binary_id = None # <
        
        self.process_data = data
        self.remote_host = remote_host
        self.certificate = certificate
        self.log_date = log_date
        
    def setupActions( self ):
        sys.path.append("actions")
        files = os.listdir("actions")
        files = filter(lambda x: x[-3:] == ".py", files)
        currentactions = [ str(x) for x in  mAlert.Action.objects.all().values_list("name", flat=True) ]
        for rname in files: 
            aclass = __import__(rname[:-3], globals(), locals())
            c = getattr(aclass, "Action") 
            obj=  c( self ) 
            # Automatically add the Action to the DB if it's not there
            # This should only work for people deving new actions
            if not obj.NAME in currentactions: 
                newAction = mAlert.Action()
                newAction.name = obj.NAME
                newAction.description = obj.DESCRIPTION
                newAction.save()
       
            self.Actions[ obj.NAME ] = obj

        
    def checkStationDup(self, hostname, ip_address):
        ###
        ### Check for stations duplicates or return station.id
        ###
        try:
            obj = stations.objects.get(hostname=hostname)
            return obj.id
        except:
            return False

    def checkEventDup(self, username, event_timestamp):
        ###
        ### Check for event duplicates, or return event.id
        ###
        try:
            obj = events.objects.get(username=username,
                                     event_timestamp=event_timestamp)
            return obj.id
        except:
            return False

    def checkBinaryDup(self, file_path, station_id):
        ###
        ### Check for binary duplicates or return binary.id
        ###
        try:
            obj = binaries.objects.get(file_path=file_path, station=station_id)
            return obj
        except:
            return False

    #def checkProcessDup(self, station_id, binary_id, binary_pid, username, cmdline):
    def checkProcessDup(self, station_id, binary_pid):
        ###
        ### Check for process duplicates, or return event.id
        ###
        try:
            #obj = running_processes.objects.get(station=station_id,
            #                                    binary=binary_id,
            #                                    pid=binary_pid,
            #                                    username=username,
            #                                    cmdline=cmdline)
            obj = running_processes.objects.get(station=station_id,
                                                pid=binary_pid)
            return obj
        except:
            return False
    
    def checkDeviceDup(self, vid, pid):
        ###
        ### Check for device duplicates, or return usb_device.id
        ###
        try:
            obj = usb_devices.objects.get(vendor_id=vid, product_id=pid)
            return obj
        except:
            return False
    
    def checkMassStorageDup(self, serial_number, caption):
        ###
        ### Check for mass storages duplicates, or return usb_mass_storage.id
        ###
        try:
            obj = usb_mass_storage.objects.get(serial_number=serial_number, caption=caption)
            return obj
        except:
            return False

    def getEntropy(self, data):
        if not data:
            return 0
        entropy = 0
        e = data.decode("hex")

        for x in range(256):
            p_x = float(e.count(chr(x))) / len(e)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def dateFormat(self):
        #print str(self.process_data["event_date"])
        event_date = self.process_data["event_date"][:14]
        frmted_time = time.mktime(time.strptime(event_date, "%Y%m%d%H%M%S"))
        return datetime.datetime.fromtimestamp(frmted_time)

    def setDateTime(self):
        return self.process_data["event_date"]
        #sdate = self.process_data["event_date"]
        #print sdate[:sdate.find(".")]
        #return sdate[:sdate.find(".")]
        #return self.process_data["event_date"] if self.process_data["event_date"] else str(datetime.datetime.now()) 
    #
    # Stores the event record for the binary, station, parent user
    #
    def store_event_information(self):
        #foreignkey = station for this event
        st = stations.objects.get(id=self.station_id)
        #foreignkey = binary for this event
        bin = binaries.objects.get(id=self.binary_id)
        #foreignkey2 = parent_binary for this event (check model's related_name if any problem)
        parent_bin = binaries.objects.get(id=self.parent_binary_id)

        ev = events()
        ev.station = st
        ev.binary = bin
        ev.parent_binary = parent_bin
        #ev.username=base64.b64decode(self.xml_dict["USER"][0])
        #ev.username=base64.b64decode(self.process_data["user"])
        ev.username = self.process_data["user"]

        try:
            ev.event_timestamp = self.dateFormat() 
        except:
            ev.event_timestamp = datetime.datetime.now()

        try:
            if self.process_data["commandline"] != "None":
                #ev.cmdline = base64.b64decode(self.xml_dict["CmdLine"][0])
                ev.cmdline = self.process_data["commandline"]
            else:
                ev.cmdline = "None"

        except:
        #    pass
            ev.cmdline = ""

        try:
            ev.flags = self.process_data["flags"]
        except:
            ev.flags = ""

        ev.creation_class_name              = self.process_data['creation_class_name']
        ev.cs_creation_class_name           = self.process_data['cs_creation_class_name']
        ev.cs_name                          = self.process_data['cs_name']
        ev.handle                           = self.process_data['handle']
        ev.handle_count                     = self.process_data['handle_count']
        ev.kernel_mode_time                 = self.process_data['kernel_mode_time']
        ev.user_mode_time                   = self.process_data['user_mode_time']
        ev.working_set_size                 = self.process_data['working_set_size']
        ev.max_working_set_size             = self.process_data['max_working_set_size']
        ev.min_working_set_size             = self.process_data['min_working_set_size']
        ev.os_creation_class_name           = self.process_data['os_creation_class_name']
        ev.os_name                          = self.process_data['os_name']
        ev.windows_version                  = self.process_data['windows_version']
        ev.other_operation_count            = self.process_data['other_operation_count']
        ev.other_transfer_count             = self.process_data['other_transfer_count']
        ev.page_faults                      = self.process_data['page_faults']
        ev.page_file_usage                  = self.process_data['page_file_usage']
        ev.peak_page_file_usage             = self.process_data['peak_page_file_usage']
        ev.peak_virtual_size                = self.process_data['peak_virtual_size']
        ev.peak_working_set_size            = self.process_data['peak_working_set_size']
        ev.priority                         = self.process_data['priority']
        ev.private_page_count               = self.process_data['private_page_count']
        ev.quota_non_paged_pool_usage       = self.process_data['quota_non_paged_pool_usage']
        ev.quota_paged_pool_usage           = self.process_data['quota_paged_pool_usage']
        ev.quota_peak_non_paged_pool_usage  = self.process_data['quota_peak_non_paged_pool_usage']
        ev.quota_peak_paged_pool_usage      = self.process_data['quota_peak_paged_pool_usage']
        ev.read_operation_count             = self.process_data['read_operation_count']
        ev.read_transfer_count              = self.process_data['read_transfer_count']
        ev.write_operation_count            = self.process_data['write_operation_count']
        ev.write_transfer_count             = self.process_data['write_transfer_count']
        ev.session_id                       = self.process_data['session_id']
        ev.thread_count                     = self.process_data['thread_count']
        ev.virtual_size                     = self.process_data['virtual_size']

        ev.save()
        # add privileges
        # self.process_data["privileges"] have an extra | at the end.
        priv_list = self.process_data["privileges"][:-1].split("|")
        for priv in priv_list:
            # If the privilege is one of our default privileges
            if priv in privilegesdict.keys():
                privilege = privileges.objects.get(name=priv)
                ev.privileges.add(privilege)
            else:
                # We might have already created the priv object
                try:
                    privilege = privileges.objects.get(name=priv)
                    ev.privileges.add(privilege)
                except:
                    privilege = privileges()
                    privilege.name = priv
                    privilege.desc = ""
                    privilege.save()
                    ev.privileges.add(privilege)
        return ev

    #
    # Stores the event record for the usb device
    #
    def store_usb_event_information(self,device):
        print "USB Event"
        #foreignkey = station for this event
        st = stations.objects.get(id=self.station_id)
        #foreignkey = binary for this event
        dev = usb_devices.objects.get(id=device.id)

        uev = usb_events()
        uev.station = st
        uev.device = dev 
        print self.process_data
        uev.event_timestamp = self.process_data['event_date'] if self.process_data['event_date'] else datetime.datetime.now()
        
        if self.process_data['notification'] ==  'Insertion':
            uev.status                    = "Connected"
        elif self.process_data['notification']  ==  'Deletion':
            uev.status                    = "Disconnected"
        
        uev.save()
    
        return uev

    #
    # Stores the event record for the usb device
    #
    def store_usb_mass_storage_event_information(self,device):
        #foreignkey = station for this event
        st = stations.objects.get(id=self.station_id)
        #foreignkey = binary for this event
        dev = usb_mass_storage.objects.get(id=device.id)
        #print str(dev)
        
        uev = usb_mass_storage_events()
        
        uev.station             = st
        uev.mass_storage_device = dev 

        """
        if self.process_data['notification'] ==  'Insertion':
           print "insertion" 
           try:
               uev.plug_date = self.dateFormat()
               print uev.plug_date
           except:
               uev.plug_date = str(datetime.datetime.now())
               print uev.plug_date


        if self.process_data['notification']  ==  'Deletion':
           print "Deletion"
           try:
               uev.unplug_date = self.dateFormat() 
           except:
               uev.unplug_date = str(datetime.datetime.now())
        
           print uev.unplug_date
        """     

        uev.event_timestamp           = self.process_data['event_date'] if self.process_data['event_date'] else datetime.datetime.now()
        
        if self.process_data['notification'] ==  'Insertion':
            uev.status                    = "Connected"
        elif self.process_data['notification']  ==  'Deletion':
            uev.status                    = "Disconnected"
        
        uev.logical_drive             = self.process_data['logicalDrive']
        uev.volume_serial_number      = self.process_data['VolumeSerialNumber']

        uev.save()
    
        return uev

    #
    # Stores the event record for the binary, station, parent user
    #
    def store_process_information(self):
        #foreignkey = station for this event
        st = stations.objects.get(id=self.station_id)
        #foreignkey = binary for this event
        bin = binaries.objects.get(id=self.binary_id)
        #foreignkey2 = parent_binary for this event (check model's related_name if any problem)
        parent_bin = binaries.objects.get(id=self.parent_binary_id)
        
        #check if the process is already in the db
        #process = self.checkProcessDup(self.station_id,
        #                               self.binary_id,
        #                               self.process_data['child_pid'],
        #                               self.process_data['user'],
        #                               self.process_data['commandline'])
        process = self.checkProcessDup(self.station_id,
                                       self.process_data['child_pid'])
        
        if not process:
            process = running_processes()
            process.station = st
            process.binary = bin
            process.parent_binary = parent_bin
            process.username = self.process_data["user"]
        
        try:
            process.creation_date = self.dateFormat() 
        except:
            process.creation_date = datetime.datetime.now()

        #CHECK THIS
        try:
            if self.process_data["commandline"] != "None":
                process.cmdline = self.process_data["commandline"]
            else:
                process.cmdline = "None"
        except:
            process.cmdline = ""
        #######################
        
        try:
            process.flags = self.process_data["flags"]
        except:
            process.flags = ""

        process.ppid                             = self.process_data['parent_pid']
        process.pid                              = self.process_data['child_pid']
        process.creation_class_name              = self.process_data['creation_class_name']
        process.cs_creation_class_name           = self.process_data['cs_creation_class_name']
        process.cs_name                          = self.process_data['cs_name']
        process.handle                           = self.process_data['handle']
        process.handle_count                     = self.process_data['handle_count']
        process.kernel_mode_time                 = self.process_data['kernel_mode_time']
        process.user_mode_time                   = self.process_data['user_mode_time']
        process.working_set_size                 = self.process_data['working_set_size']
        process.max_working_set_size             = self.process_data['max_working_set_size']
        process.min_working_set_size             = self.process_data['min_working_set_size']
        process.os_creation_class_name           = self.process_data['os_creation_class_name']
        process.os_name                          = self.process_data['os_name']
        process.windows_version                  = self.process_data['windows_version']
        process.other_operation_count            = self.process_data['other_operation_count']
        process.other_transfer_count             = self.process_data['other_transfer_count']
        process.page_faults                      = self.process_data['page_faults']
        process.page_file_usage                  = self.process_data['page_file_usage']
        process.peak_page_file_usage             = self.process_data['peak_page_file_usage']
        process.peak_virtual_size                = self.process_data['peak_virtual_size']
        process.peak_working_set_size            = self.process_data['peak_working_set_size']
        process.priority                         = self.process_data['priority']
        process.private_page_count               = self.process_data['private_page_count']
        process.quota_non_paged_pool_usage       = self.process_data['quota_non_paged_pool_usage']
        process.quota_paged_pool_usage           = self.process_data['quota_paged_pool_usage']
        process.quota_peak_non_paged_pool_usage  = self.process_data['quota_peak_non_paged_pool_usage']
        process.quota_peak_paged_pool_usage      = self.process_data['quota_peak_paged_pool_usage']
        process.read_operation_count             = self.process_data['read_operation_count']
        process.read_transfer_count              = self.process_data['read_transfer_count']
        process.write_operation_count            = self.process_data['write_operation_count']
        process.write_transfer_count             = self.process_data['write_transfer_count']
        process.session_id                       = self.process_data['session_id']
        process.thread_count                     = self.process_data['thread_count']
        process.virtual_size                     = self.process_data['virtual_size']
        process.log_date                         = self.log_date

        process.save()
        # add privileges
        
        priv_list = self.process_data["privileges"][:-1].split("|")
        for priv in priv_list:
            # If the privilege is one of our default privileges
            if priv in privilegesdict.keys():
                privilege = privileges.objects.get(name=priv)
                process.privileges.add(privilege)
            else:
                # We might have already created the priv object
                try:
                    privilege = privileges.objects.get(name=priv)
                    process.privileges.add(privilege)
                except:
                    privilege = privileges()
                    privilege.name = priv
                    privilege.desc = ""
                    privilege.save()
                    process.privileges.add(privilege)
        return process 

    #
    # Stores information about the executed binary.
    #
    def store_binary_information(self, binary_path, parent=False, event=True):
        bin = []
        binary = self.checkBinaryDup(binary_path, self.station_id)

        if binary:
            if event:
                binary.last_execution = datetime.datetime.now()
            else:
                binary.last_execution = self.dateFormat() 
            binary.save()
            if parent:
                self.parent_binary_id = binary.id
            else:
                self.binary_id = binary.id

        else:
            # binary not found, hence no dup
            st = stations.objects.get(id=self.station_id)
            bin = binaries()
            bin.station = st
            bin.file_path = binary_path
            bin.last_execution = datetime.datetime.now()

            try:
                bin.arch = self.process_data["arch"]
            except:
                bin.arch = "N/A"

            if not parent:
                bin.binary_sha1 = self.process_data["child_hash"]
                bin.binary_sha256 = self.process_data["child_hash_sha256"]
                bin.binary_md5    = self.process_data["child_hash_md5"]
                bin.code_section_sha1 = self.process_data["code_hash"]

                try:
                    bin.code_section = self.process_data["code"]
                except:
                    bin.code_section = ""

                try:
                    code_entropy = self.getEntropy(self.process_data['code'])

                except:
                    code_entropy = 0.0

                bin.entropy = code_entropy

                try:
                    bin.pid = self.process_data["child_pid"]
                except:
                    bin.pid = "-1"

                bin.filesize = self.process_data["child_file_size"]
                bin.save()
                self.binary_id = bin.id

            else:
                bin.binary_sha1 = self.process_data["parent_hash"]
                bin.binary_sha256 = self.process_data["parent_hash_sha256"]
                bin.binary_md5 = self.process_data["parent_hash_md5"]
                bin.code_section_sha1 = self.process_data["parent_code_hash"]

                try:
                    bin.code_section = self.process_data["parent_code"]
                except:
                    bin.code_section = ""

                try:
                    code_entropy = self.getEntropy(self.process_data["parent_code"])
                except:
                    code_entropy = 0.0

                bin.entropy = code_entropy

                try:
                    bin.pid = self.process_data["parent_pid"]
                except:
                    bin.pid = "-1"

                bin.filesize = self.process_data["parent_file_size"]

                bin.save()
                self.parent_binary_id = bin.id

        return bin

    #
    # Stores information about usb devices.
    #
    def store_usb_device_information(self):
        
        usb_dev = self.checkDeviceDup(self.process_data["Vendor_ID"], self.process_data["Product_ID"])

        if usb_dev:
            usb_dev.last_connection = datetime.datetime.now()
            if not usb_dev.usb_class:
                usb_dev.usb_class = self.process_data["USB_Class"]
            if not usb_dev.caption:
                usb_dev.caption = self.process_data["Caption"]            
            usb_dev.save()
        else:
            usb_dev = usb_devices()
            usb_dev.last_connection = datetime.datetime.now()
            usb_dev.vendor_id = self.process_data["Vendor_ID"]
            usb_dev.product_id = self.process_data["Product_ID"]
            usb_dev.usb_class = self.process_data["USB_Class"]
            usb_dev.caption = self.process_data["Caption"]

            usb_dev.save()

        return usb_dev 
    
    #
    # Stores information about usb mass storage devices.
    #
    def store_usb_mass_storage_information(self, serial_number, pnp_device_id):
        
        usb_dev = self.checkMassStorageDup(serial_number, pnp_device_id)

        if usb_dev:
            usb_dev.last_connection = datetime.datetime.now()
            #print "Device exits" 
            usb_dev.save()
        else:
            # device not found, hence no dup
            #st = stations.objects.get(id=self.station_id)
            usb_dev = usb_mass_storage()
            
            usb_dev.last_connection            = datetime.datetime.now()
            #usb_dev.uid                        = device_uid 
            usb_dev.serial_number              = serial_number 
            usb_dev.bytes_per_sector           = self.process_data["BytesPerSector"]
            usb_dev.capabilities               = self.process_data["Capabilities"]
            usb_dev.capability_descriptions    = self.process_data["CapabilityDescriptions"]
            usb_dev.caption                    = self.process_data["Caption"]
            usb_dev.config_manager_error_code  = self.process_data["ConfigManagerErrorCode"]
            usb_dev.config_manager_user_config = self.process_data["ConfigManagerUserConfig"]
            usb_dev.creation_class_name        = self.process_data["CreationClassName"]
            usb_dev.description                = self.process_data["Description"]
            usb_dev.dev_id                     = self.process_data["DeviceID"]
            usb_dev.firmware_revision          = self.process_data["FirmwareRevision"]
            usb_dev.index                      = self.process_data["Index"]
            usb_dev.interface_type             = self.process_data["InterfaceType"]
            usb_dev.manufacturer               = self.process_data["Manufacturer"]
            usb_dev.media_loaded               = self.process_data["MediaLoaded"]
            usb_dev.media_type                 = self.process_data["MediaType"]
            usb_dev.model                      = self.process_data["Model"]
            usb_dev.name                       = self.process_data["Name"]
            usb_dev.partitions                 = self.process_data["Partitions"]
            usb_dev.pnp_device_id              = self.process_data["PNPDeviceID"]
            usb_dev.sectors_per_track          = self.process_data["SectorsPerTrack"]
            usb_dev.signature                  = self.process_data["Signature"]
            usb_dev.size                       = self.process_data["Size"]
            usb_dev.status                     = self.process_data["Status"]
            usb_dev.system_creation_class_name = self.process_data["SystemCreationClassName"]
            usb_dev.total_cylinders            = self.process_data["TotalCylinders"]
            usb_dev.total_heads                = self.process_data["TotalHeads"]
            usb_dev.total_sectors              = self.process_data["TotalSectors"]
            usb_dev.total_tracks               = self.process_data["TotalTracks"]

            usb_dev.save()

        return usb_dev 

    #
    #
    # Stores station-specific information in the database
    #
    def store_station_information(self):
        station_id = self.checkStationDup(self.process_data["station"],
                                          self.remote_host)

        if station_id:
            st = stations.objects.get(id=station_id)
            st.last_seen = datetime.datetime.now()
            st.save()
            self.station_id = station_id
        else:

            # station not found, hence no dup
            st = stations()
            st.hostname   = self.process_data["station"]
            st.ip_address = self.remote_host
            st.last_seen = datetime.datetime.now()
            st.certificate = self.certificate
            st.save()
            self.station_id = st.id

    def store_uniqueness_information(self, event):
        child_hash = self.process_data["child_hash"]
        child_commandline = self.process_data["commandline"]

        h = hashlib.sha1()
        h.update(child_hash + child_commandline)
        unique_hash = h.hexdigest()

        try:
            unique_executions.objects.get(hash=unique_hash)
            return
        except:
            binary = self.checkBinaryDup(self.process_data["child_binary"],
                                         self.station_id)
            execution = unique_executions()
            execution.hash = unique_hash
            execution.binary = binaries.objects.get(id=binary.id)
            execution.event = event
            execution.first_run = datetime.datetime.now()
            execution.save()
    
    def store_uniqueness_process_information(self, process):
        child_hash = self.process_data["child_hash"]
        child_commandline = self.process_data["commandline"]
        child_pid = self.process_data["child_pid"]

        h = hashlib.sha1()
        h.update(child_hash + child_commandline + str(child_pid))
        unique_hash = h.hexdigest()

        try:
            unique_processes.objects.get(hash=unique_hash)
            return
        except:
            binary = self.checkBinaryDup(self.process_data["child_binary"],
                                         self.station_id)
            up = unique_processes()
            up.hash = unique_hash
            up.binary = binaries.objects.get(id=binary.id)
            up.process = process 
            #up.first_run = datetime.datetime.now()
            up.save()

    #
    # Function that handles getting all the database bits and pieces stored.
    #
    def store_uppriv_event(self):

        # First let's store the station relevant information
        self.store_station_information()

        # Now let's store the binary information
        child_binary = self.store_binary_information(self.process_data["child_binary"])

        # If this is a new binary send an email alert
        if child_binary and child_binary.bin.count() == 1 and ENABLE_EMAIL_ALERTS:
            self.send_email_alert(self.process_data)

        parent_binary = self.store_binary_information(self.process_data["parent_binary"],
                                                      parent=True)

        # Create an event record
        event = self.store_event_information()

        self.store_uniqueness_information(event)

        # Filters checking
        #filters = [ExecutionFilter, TestFilter]
        filters = []
        for mName in dir(mAlert):
            # We loop over all the models on the alerts/ folder, 
            # finding every class except "Action" which should only be Filters
            filter_type = getattr(mAlert, mName)
            try:
                if issubclass(filter_type, models.Model) and mName != "Action":
                    filters.append( filter_type )
            except TypeError:
                continue
         
        for filter_type in filters:
            for flt in filter_type.objects.all():
                if flt.filter(event):
                    for action in flt.actions.all():
                        if action.name in self.Actions.keys():
                            obj = self.Actions[ action.name ]  
                            obj.Act( event, flt ) 
        return event
    
    #
    # Function that handles getting all the database bits and pieces stored.
    #
    def store_uppriv_usb_mass_storage_event(self):

        # First let's store the station relevant information
        self.store_station_information()

        # Now let's store the usb device information
        usb_mass_storage_device = self.store_usb_mass_storage_information(self.process_data["SerialNumber"],self.process_data["Caption"])

        # If this is a new binary send an email alert
        #if child_binary and child_binary.bin.count() == 1 and ENABLE_EMAIL_ALERTS:
        #    self.send_email_alert(self.process_data)

        # Create an event record:w

        usb_mass_storage_event = self.store_usb_mass_storage_event_information(usb_mass_storage_device)

    #
    # Function that handles getting all the database bits and pieces stored.
    #
    def store_uppriv_usb_event(self):

        # First let's store the station relevant information
        self.store_station_information()

        # Now let's store the usb device information
        usb_device = self.store_usb_device_information()

        # If this is a new binary send an email alert
        #if child_binary and child_binary.bin.count() == 1 and ENABLE_EMAIL_ALERTS:
        #    self.send_email_alert(self.process_data)

        # Create an event record:w

        usb_event = self.store_usb_event_information(usb_device)

        #self.store_uniqueness_information(event)
    
    #
    # Function that handles getting all the database bits and pieces stored.
    #
    def store_uppriv_process(self):

        # First let's store the station relevant information
        self.store_station_information()

        # Now let's store the binary information
        child_binary = self.store_binary_information(self.process_data["child_binary"],parent=False,event=False)

        # If this is a new binary send an email alert TODO: Analize this
        #if child_binary and child_binary.bin.count() == 1 and ENABLE_EMAIL_ALERTS:
        #    self.send_email_alert(self.process_data)

        parent_binary = self.store_binary_information(self.process_data["parent_binary"],
                                                      parent=True,
                                                      event=False)

        # Create a process record
        process = self.store_process_information()

        return process 

    def send_email_alert(self, event, flt):
        """
        username = models.CharField(max_length=64)
        event_timestamp = models.DateTimeField()
        binary = models.ForeignKey(binaries,related_name='bin')
        parent_binary = models.ForeignKey(binaries,related_name='parent_bin')
        station = models.ForeignKey(stations,related_name="stations_id")
        """
        filter_fields = flt._meta.get_all_field_names()
        filter_fields.remove('id')
        filter_fields.remove('actions')
        field_data = ""
        for field in filter_fields:
            field_data += '%s: %s \n' % (field, str(getattr(flt, field)))

        data = {}
        data['username'] = event.station.hostname
        data['ip'] = event.station.ip_address
        data['binary'] = event.binary.file_path
        data['parent_binary'] = event.parent_binary.file_path
        data['date'] = event.event_timestamp
        data['filter'] = flt
        data['filter_data'] = field_data

        body = """
        The following filter has been triggered:

        Filter: %(filter)s
        Data: %(filter_data)s

        Event Information:

        Username: %(username)s
        Station:  %(station)s
        Binary:   %(binary)s
        Parent binary: %(parent_binary)s
        Date: %(date)s
        """
        send_mail('El Jefe - Alert',
                  body,
                  'alert@eljefe.immunityinc.com',
                  ['admin@immuntyinc.com'],
                  fail_silently=False)




