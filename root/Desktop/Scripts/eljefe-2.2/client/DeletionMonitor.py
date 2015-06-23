# Copyright (C) 2010-2014 Immunity Inc.
# This file is part of El Jefe - http://www.immunityinc.com/products-eljefe.shtml
# See the file 'docs/LICENSE' for copying permission.


import wmi
import pythoncom
import threading
import os

exit_threads   = False
parent_records = {}

class deletion_monitor(threading.Thread):
    
    def __init__(self):
        threading.Thread.__init__(self)
        self.setDaemon(True)
    
    def run(self):
        global exit_threads
	
        print "Starting Deletion monitor"
        pythoncom.CoInitialize()
	
        try:
            c = wmi.WMI()

            watcher = c.watch_for (
                notification_type="Deletion",
                wmi_class="Win32_Process",
                delay_secs=1,
            )
					    
            while not exit_threads:		
                w = watcher()
                print "Deleted process [%d] %s" % (w.ProcessId, str(w.ExecutablePath))
                if w.ExecutablePath:
                    parent_records[str(w.ProcessId)] = w.ExecutablePath
                    #print "Parents : " + str(parent_records)
                else:
                    print w
		
        except KeyboardInterrupt:
            exit_threads=True
            raise
        except:	    
            raise
        finally:
            pythoncom.CoUninitialize ()
	     	
def get_parent(pid):
    
    if not parent_records.has_key(str(pid)) or not parent_records[str(pid)]:
        return None
        
    return parent_records.pop(str(pid))

def clean_parent_list():
        parent_records.clear()

        
if __name__ == '__main__':
    
    deletion_monitor().start()  
    
    try:	
        print '\nStarting Deletion Server'
        print '\nUse Control-C to exit'
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print "Exiting"    
        exit(0)	
     