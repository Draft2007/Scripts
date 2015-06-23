# Copyright (C) 2010-2014 Immunity Inc.
# This file is part of El Jefe - http://www.immunityinc.com/products-eljefe.shtml
# See the file 'docs/LICENSE' for copying permission.

## You can use this script to run ElJefe manually

from ConfParser import conf_parser
from CreationMonitor import *
from DeletionMonitor import *
from USBMonitor import *
from UMSMonitor import *
import sys
sys.path.append(".")

debug_file_path = os.path.dirname(os.path.realpath(sys.argv[0]))
file_path = os.path.join(debug_file_path, "ElJefe.log")


def start_debug( debug_level = 0 ):
    
    global debug_file
    global exit_threads

    if debug_level > 0:
        debug_file = open(file_path, "w", 0) 

    if debug_level == 1:
        sys.stderr = debug_file 

    if debug_level > 1 :
        sys.stderr = debug_file 
        sys.stdout = debug_file 

if __name__ == '__main__':

    global debug_file
    # start log 
    start_debug( debug_level = 1 )
   
    cm = creation_monitor()
    dm = deletion_monitor()
    pm = process_monitor()
    um = usb_monitor()
    mm = usb_mass_storage_monitor()
    
    try:	  
        # start the creation monitor    
        cm.start()
        # start the deletion monitor
        dm.start()
        # start the running process monitor
        pm.start()        
        # start the USB  monitor
        um.start()        
        # start the mass storage monitor
        mm.start()        
        #print '\nStarting Deletion Server'
        print '\nUse Control-C to exit'
        #for thread in threading.enumerate():
        #    if thread is not threading.currentThread():
        #        thread.join()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print "Exiting"
        cm.stop()
        dm.stop()
        pm.stop()
        um.stop()
        mm.stop()
        exit(0)
    except Exception, e:
        print str(e)
        exit(1)
    finally:
        debug_file.close()
    
