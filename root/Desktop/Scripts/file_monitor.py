import tempfile
import threading
import win32file
import win32con
import os

# these are the common temp file directories
dirs_to_monitor = ["C:\\WINDOWS\\Temp",tempfile.gettempdir()]

# file modification constants
FILE_CREATED        = 1
FILE_DELETED        = 2
FILE_MODIFIED       = 3
FILE_RENAMED_FROM   = 4
FILE_RENAMED_TO     = 5

def start_monitor(path_to_watch):
    # we create a thread for each monitoring run
    FILE_LIST_DIRECTORY = 0x0001
    # aquire a handle to the directory that we want to monitor
    h_directory = win32file.CreateFile(path_to_watch,FILE_LIST_DIRECTORY,win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,None,win32con.OPEN_EXISTING,win32con.FILE_FLAG_BACKUP_SEMANTICS,None)
    # 3
    while 1:
        try:
            results = win32file.ReadDirectoryChangesW(h_directory,1024,True,win32con.FILE_NOTIFY_CHANGE_FILE_NAME,win32con.FILE_NOTIFY_CHANGE_DIR_NAME,win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES,win32con.FILE_NOTIFY_CHANGE_SIZE,win32con.FILE_NOTIFY_CHANGE_LAST_WRITE,win32con.FILE_NOTIFY_CHANGE_SECURITY,None,None)
            # Recieve filname of target file that has changed and type of
            # event that happeed
            for action,file_name in results:
                full_filename = os.path.join(path_to_watch, file_name)
                
                # print useful info of what happened with a particular file
                if action == FILE_CREATED:
                    print "[ + ] Created %s" % full_filename
                elif action == FILE_DELETED:
                    print "[ - ] Deleted %s" % full_filename
                elif action == FILE_MODIFIED:
                    print "[ * ] Modified %s" % full_filename
                    
                    # 5 dump out the file contents
                    print "[vvv] Dumping contents..."
                    
                    try:
                        fd = open(full_filename,"rb")
                        contents = fd.read()
                        fd.close()
                        print contents
                        print "[^^^] Dump complete."
                    except:
                        print "[!!!] Failed."
                        
                elif action == FILE_RENAMED_FROM:
                    print "[ > ] Renamed from: %s" % full_filename
                elif action == FILE_RENAMED_TO:
                    print "[ < ] Renamed to: %s" % full_filename
                else:
                    print "[???] Unknown: %s" % full_filename
        except:
            pass
        
for path in dirs_to_monitor:
    monitor_thread = threading.Thread(target=start_monitor,args=(path,))
    print "Spawning monitoring thread for path: %s" % path
    monitor_thread.start()