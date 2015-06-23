# Copyright (C) 2010-2014 Immunity Inc.
# This file is part of El Jefe - http://www.immunityinc.com/products-eljefe.shtml
# See the file 'docs/LICENSE' for copying permission.

## Run ElJefe as a Windows service 
## ****Used only for testing**** 
## Usage : python ElJefeWinService.py install (or remove)
## then  : python ElJefeWinService.py start   (or stop)

import win32service
import win32serviceutil
import win32api
import win32con
import win32event
import win32evtlogutil
import os, sys, string, time
import inspect


from CreationMonitor import *
from DeletionMonitor import *
from BinaryProviderServer import *

sys.path.append(".")

   def __init__(self, args):
      win32serviceutil.ServiceFramework.__init__(self, args)
      self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
      self.server = DeletionMonitorXMLRPCServer((DELHOST,DELPORT))
        
   def SvcStop(self):
      self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
      win32event.SetEvent(self.hWaitStop)
      self.server.stop()
      
   def SvcDoRun(self):
      import servicemanager
      # Write a 'started' event to the event log...
      win32evtlogutil.ReportEvent(self._svc_name_,
                                 servicemanager.PYS_SERVICE_STARTED,
                                 0, # category
                                 servicemanager.EVENTLOG_INFORMATION_TYPE,
                                 (self._svc_name_, ''))

      creation_monitor().start()	
	 # start the deletion monitor
      deletion_monitor().start()
	 # start the binary provider server
      binary_provider_server().start()
	 # start deletion server   	
      self.server.start()


      # wait for beeing stopped...
      win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

      # and write a 'stopped' event to the event log.
      win32evtlogutil.ReportEvent(self._svc_name_,
                                 servicemanager.PYS_SERVICE_STOPPED,
                                 0, # category
                                 servicemanager.EVENTLOG_INFORMATION_TYPE,
                                 (self._svc_name_, ''))


                  
if __name__ == '__main__':
   win32serviceutil.HandleCommandLine(ElJefeWinService)
