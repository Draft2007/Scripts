# Copyright (C) 2010-2014 Immunity Inc.
# This file is part of El Jefe - http://www.immunityinc.com/products-eljefe.shtml
# See the file 'docs/LICENSE' for copying permission.
# USB Mass Storage Module

import wmi
import sys 
import pythoncom
import threading
import os
import time
import datetime
import socket
import xmlrpclib
import binascii 
from CreationMonitor import auth_transport 
from CreationMonitor import config,key,cert,ca_cert,server_cert_path 


exit_threads   = False


#
# Send the process event off to our logging server. 
#
def send_usb_data(usb_record):

    global config
    log_host = config.get('host')
    log_port = int(config.get('port'))
    trans = auth_transport(key, cert, ca_cert)
    print "send_usb_data():Trying to send usb data to: %s:%d" % (log_host,log_port)
    try:
        server = xmlrpclib.Server('https://%s:%s' % (log_host,log_port),transport = trans)
        response = server.save_usb_mass_storage_record(usb_record)
    except KeyboardInterrupt:
        exit_threads = True
        raise
    except:
        print "UMSMonitor - Exception: " + str(sys.exc_info())
        raise

    if response:
        print response

def get_serial_number(serial):
  
    if serial:
        #Do something to check if is binary
        return binascii.hexlify(serial)
    else:
        return "N/A"

def process_usb_record(notification,actionTime,usb,logicalDrive):
    """
    From: http://msdn.microsoft.com/en-us/library/aa394504(v=vs.85).aspx
   [Provider("CIMWin32")]class Win32_USBController : CIM_USBController
{
  uint16   Availability;
  string   Caption;
  uint32   ConfigManagerErrorCode;
  boolean  ConfigManagerUserConfig;
  string   CreationClassName;
  string   Description;
  string   DeviceID;
  boolean  ErrorCleared;
  string   ErrorDescription;
  datetime InstallDate;
  uint32   LastErrorCode;
  string   Manufacturer;
  uint32   MaxNumberControlled;
  string   Name;
  string   PNPDeviceID;
  uint16   PowerManagementCapabilities[];
  boolean  PowerManagementSupported;
  uint16   ProtocolSupported;
  string   Status;
  uint16   StatusInfo;
  string   SystemCreationClassName;
  string   SystemName;
  datetime TimeOfLastReset;
  
  [Provider("CIMWin32")]class Win32_USBControllerDevice : CIM_ControlledBy
{
  uint16            AccessState;
  CIM_USBController REF Antecedent;
  CIM_LogicalDevice REF Dependent;
  uint32            NegotiatedDataWidth;
  uint64            NegotiatedSpeed;
  uint32            NumberOfHardResets;
  uint32            NumberOfSoftResets;
};
};"""
    process_record = {}
    process_record['station']                           = socket.gethostname()
    process_record['BytesPerSector']                    = usb.BytesPerSector if usb.BytesPerSector else "N/A"
    process_record['Capabilities']                      = usb.Capabilities if usb.Capabilities else "N/A"
    process_record['CapabilityDescriptions']            = usb.CapabilityDescriptions if usb.CapabilityDescriptions else "N/A" 
    process_record['Caption']                           = usb.Caption
    process_record['ConfigManagerErrorCode']            = usb.ConfigManagerErrorCode
    process_record['ConfigManagerUserConfig']           = usb.ConfigManagerUserConfig
    process_record['CreationClassName']                 = usb.CreationClassName
    process_record['Description']                       = usb.Description
    process_record['DeviceID']                          = usb.DeviceID
    #process_record['InstallDate']                       = usb.InstallDate
    process_record['FirmwareRevision']                  = usb.FirmwareRevision
    process_record['Index']                             = usb.Index
    process_record['InterfaceType']                     = usb.InterfaceType
    process_record['Manufacturer']                      = usb.Manufacturer
    process_record['MediaLoaded']                       = usb.MediaLoaded if usb.MediaLoaded else "N/A"
    process_record['MediaType']                         = usb.MediaType if usb.MediaType else "N/A"
    process_record['Model']                             = usb.Model
    process_record['Name']                              = usb.Name
    process_record['Partitions']                        = usb.Partitions
    process_record['PNPDeviceID']                       = usb.PNPDeviceID
    process_record['SectorsPerTrack']                   = usb.SectorsPerTrack if usb.SectorsPerTrack else "N/A"
    process_record['Signature']                         = usb.Signature
    process_record['Size']                              = usb.Size if usb.Size else "N/A"
    process_record['Status']                            = usb.Status
    process_record['SerialNumber']                      = get_serial_number(usb.SerialNumber) 
    #process_record['SerialNumber']                      = usb.SerialNumber
    #process_record['StatusInfo']                        = usb.StatusInfo
    process_record['SystemCreationClassName']           = usb.SystemCreationClassName
    process_record['TotalCylinders']                    = usb.TotalCylinders if usb.TotalCylinders else "N/A" 
    process_record['TotalHeads']                        = usb.TotalHeads if usb.TotalHeads else "N/A"
    process_record['TotalSectors']                      = usb.TotalSectors if usb.TotalSectors else "N/A"
    process_record['TotalTracks']                       = usb.TotalTracks if usb.TotalTracks else "N/A"
    process_record['TracksPerCylinder']                 = usb.TracksPerCylinder if usb.TracksPerCylinder else "N/A"
    #process_record['SystemName']                        = usb.SystemName
    #process_record['user']                              = "%s\\%s" % (group,username)
    process_record['notification']                      = notification
    process_record['event_date']                        = actionTime
    process_record['logicalDrive']                      = (logicalDrive.Caption if logicalDrive else "N/A") if logicalDrive else "N/A"
    process_record['VolumeSerialNumber']                = (logicalDrive.VolumeSerialNumber if logicalDrive else "N/A") if logicalDrive else "N/A"


    try:
        #print process_record
        send_usb_data(process_record)
        print "Message sent!"
    except:
        print "Exception: " + str(sys.exc_info())
        #print process_record
        raise


class usb_mass_storage_monitor(threading.Thread):
    
    def __init__(self):
        threading.Thread.__init__(self)
        self.setDaemon(True)
    
    def run(self):
        global exit_threads
        print "Starting USB Mass Storage Monitor"
        pythoncom.CoInitialize()
        # instantiate the WMI interface
        c = wmi.WMI()
        while not exit_threads:
            try:
                #watch for USB disk insertions
                watcher1 = c.watch_for(notification_type="Creation",wmi_class="Win32_DiskDrive",InterfaceType="USB")
                watcher2 = c.watch_for(notification_type="Deletion",wmi_class="Win32_DiskDrive",InterfaceType="USB")
                while True:
                    try:
                        usb = watcher1(timeout_ms=20000)
                        controller = c.Win32_USBControllerDevice
                        insertionTime = str(datetime.datetime.now())
                        #print "Time: " + str(insertionTime)
                        #print usb
                        logical = None
                        for partition in usb.associators ("Win32_DiskDriveToDiskPartition"):
                            for logical_disk in partition.associators ("Win32_LogicalDiskToPartition"):
                                #print logical
                                logical = logical_disk
                                #print usb.Caption, partition.Caption, logical_disk.Caption
                                #print logical_disk
                        process_usb_record("Insertion",insertionTime,usb,logical)
                    except wmi.x_wmi_timed_out:
                        pass
                    try:
                        usb = watcher2(timeout_ms=20000)
                        controller = c.Win32_USBControllerDevice
                        deletionTime = str(datetime.datetime.now())
                        #print controller
                        process_usb_record("Deletion",deletionTime,usb,None)
                    except wmi.x_wmi_timed_out:
                        pass
            except KeyboardInterrupt:
                exit_threads = True
                print "1"
                raise
            except:
                #print "2"
                print "UMSMonitor - Exception: " + str(sys.exc_info())
                raise
            finally:
                pythoncom.CoUninitialize ()	

        
if __name__ == '__main__':
    
    usb_mass_storage_monitor().start()  
    
    try:	
        print '\nStarting USB Mass Storage Monitor'
        print '\nUse Control-C to exit'
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print "Exiting"    
        exit(0)	
     
