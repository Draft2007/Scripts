# Copyright (C) 2010-2014 Immunity Inc.
# This file is part of El Jefe - http://www.immunityinc.com/products-eljefe.shtml
# See the file 'docs/LICENSE' for copying permission.

import binascii
import string
import wmi
import sys 
import pythoncom
import threading
import os
import re
import time
import datetime
import socket
import xmlrpclib
from CreationMonitor import auth_transport 
from CreationMonitor import config,key,cert,ca_cert,server_cert_path 

exit_threads   = False

def split_usb_devices(entities):
    devices = {}
    for elem in entities:
        unique_id = get_vid_pid(elem.DeviceID)
        if not unique_id:
            continue

        if unique_id in devices:
            devices[unique_id].append(elem)
        else:
            devices[unique_id] = [elem]
            
    return devices
    
def get_device_id(usb_device):
    device_id_start = usb_device.Dependent.find('=') + 2
    device_id =  usb_device.Dependent[device_id_start:-1]
    device_id = device_id.replace('\\\\','\\')
    return device_id 

def get_usb_class(pnp_entity):
    if (pnp_entity.CompatibleID == None):
        return
    if isinstance(pnp_entity.CompatibleID, tuple):
        compatible_id = pnp_entity.CompatibleID[0]
    else:
        compatible_id = pnp_entity.CompatibleID
    
    if not re.search('Class_[0-9A-Fa-f][0-9A-Fa-f]',compatible_id):
        return 

    usb_class = re.search('Class_[0-9A-Fa-f][0-9A-Fa-f]',compatible_id).group()
    usb_subclass = re.search('SubClass_[0-9A-Fa-f][0-9A-Fa-f]',compatible_id).group()
    usb_protocol = re.search('Prot_[0-9A-Fa-f][0-9A-Fa-f]',compatible_id).group()

    usb_class = usb_class[-2:]
    usb_subclass = usb_subclass[-2:]
    usb_protocol = usb_protocol[-2:]
    
    try:
        usb_class = int(usb_class,16)
        usb_subclass = int(usb_subclass,16)
        usb_protocol = int(usb_protocol,16)

        return usb_class,usb_subclass,usb_protocol
    except:
        return
    
def get_vid_pid(device_id):
    try:
        vid = re.search('VID_[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]',device_id).group()
        vid = vid[-4:]
        
        pid = re.search('PID_[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]',device_id).group()
        pid = pid[-4:]
    
        return vid, pid
    
    except:
        return
    
#
# Send the process event off to our logging server. 
#
def send_usb_data(usb_record):

    global config
    log_host = config.get('host')
    log_port = int(config.get('port'))
    trans = auth_transport(key, cert, ca_cert)
    print "Trying to send usb data to: %s:%d" % (log_host,log_port)
    try:
        server = xmlrpclib.Server('https://%s:%s' % (log_host,log_port),transport = trans)
        response = server.save_usb_record(usb_record)
    except KeyboardInterrupt:
        exit_threads = True
        raise
    except:
        print "USBMonitor - Exception: " + str(sys.exc_info())
        raise

    if response:
        print response

def process_usb_record(notification,vid, pid, usb_classes = [], captions = []):
    usb_info = []
    for info in usb_classes:
        usb_info.append('/'.join(map(str,list(info))))
        
    process_record = {}
    process_record["Vendor_ID"] = vid
    process_record["Product_ID"] = pid
    process_record["USB_Class"] = "|".join(usb_info)
    process_record["Caption"] = "|".join(captions) 
    process_record["notification"] = notification
    process_record["station"] = socket.gethostname()
    process_record["event_date"] = str(datetime.datetime.now())
    
    try:
        #print process_record
        send_usb_data(process_record)
        print "Message sent!"
    except:
        print "Exception: " + str(sys.exc_info())
        raise
        

class usb_monitor(threading.Thread):
    
    def __init__(self):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.created_pnp_entities = []
        self.deleted_devices = set()
        self.pnp_entities = []
        self.mass_storage_list  = list()

    def run(self):
        global exit_threads
        print "Starting USB monitor"
        pythoncom.CoInitialize()
        # instantiate the WMI interface
        c = wmi.WMI()
        

        while not exit_threads:
            try:
                #watch for USB insertions
                watcher1 = c.watch_for(notification_type="Creation",
                                        wmi_class="Win32_USBControllerDevice")
                watcher2 = c.watch_for(notification_type="Deletion",
                                        wmi_class="Win32_USBControllerDevice")
                while True:
                    try:
                        usb = watcher1(timeout_ms=4000)
                        device_id = get_device_id(usb)
                        for elem in wmi.WMI().Win32_PnPEntity():
                            if device_id == elem.DeviceID:
                                #print elem
                                usb_info = get_usb_class(elem)
                                usb_class = 0x0    
                                
                                if usb_info:
                                    usb_class = usb_info[0]
                                
                                if usb_class == 0x8 or \
                                    'USBSTOR' in elem.DeviceID:
                                    print 'Mass Storage Connected: Skiping'
                                    self.mass_storage_list.append(elem.DeviceID)
                                    continue
                                self.created_pnp_entities.append(elem)
                            
                    except wmi.x_wmi_timed_out:
                        if self.created_pnp_entities:
                            devices = split_usb_devices(self.created_pnp_entities)
                                    
                            for device in devices:
                                usb_classes = set()
                                captions = set()
                                device_ids = set()
                                for elem in devices[device]:
                                    usb_info = get_usb_class(elem)
                                    # usb_cls value can be 0 so we can't just use if usb_cls
                                    if usb_info != None:
                                        usb_classes.add(usb_info)
                                    if elem.Caption:
                                        captions.add(elem.Caption)
                                      
                                vid, pid = device
                                process_usb_record("Insertion", vid, pid,
                                                    list(usb_classes), 
                                                    list(captions)
                                                   )
                            
                            self.created_pnp_entities = []
                            
                    try:
                        usb = watcher2(timeout_ms=4000)
                        device_id = get_device_id(usb)
                        
                        if device_id not in self.mass_storage_list:
                            #print usb
                            self.deleted_devices.add(get_vid_pid(device_id))
                        else:
                            self.mass_storage_list.remove(device_id)

                    except wmi.x_wmi_timed_out:
                        if self.deleted_devices:
                            for device in self.deleted_devices:
                                if device:
                                    #print device
                                    vid, pid = device
                                    process_usb_record("Deletion", vid, pid)

                            self.deleted_devices = set() 

            except KeyboardInterrupt:
                exit_threads = True
                print "1"
                raise
            except:
                print "USBMonitor - Exception: " + str(sys.exc_info())
                raise
            finally:
                pythoncom.CoUninitialize ()	

        
if __name__ == '__main__':
    
    usb_monitor().start()  
    
    try:
        print '\nStarting USB monitor'
        print '\nUse Control-C to exit'
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print "Exiting"    
        exit(0)	
     
