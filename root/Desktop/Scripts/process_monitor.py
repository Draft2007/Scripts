import win32con
import win32api
import win32security

import wmi
import sys
import os

def get_process_privileges(pid):
    try:
        # 1 obtain a handle to the target process
        hproc = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION,False,pid)
        
        # 2 open the main process token
        htok = win32security.OpenProcessToken(hproc,win32con.TOKEN_QUERY)
        
        # 3 retrieve the list of privileges enabled
        privs = win32security.GetTokenInformation(htok, win32security.TokenPrivileges)
        
        # iterate over privileges and output the ones that are enabled
        priv_list = ""
        for i in privs:
            # check if the privilege is enabled
            if i[1] == 3:
                priv_list += "%s|" % win32security.LookupPrivilegeName(None,i[0])
    except:
        priv_list = "N/A"
        
    return priv_list

def log_to_file(message):
    fd = open("process_monitor_log.csv", "ab")
    fd.write("%s\r\n" % message)
    fd.close()
    
    return

# create a log file header
log_to_file("Time,User,Executable,CommandLine,PID,Parent PID,Privileges")

# 1 instantiate the WMI interface
c = wmi.WMI()

# 2 create our process monitor and tell it to watch for 
# process creation event
process_watcher = c.Win32_Process.watch_for("creation")

while True:
    try:
        # 3 Enter a loop until process watcher returns new process event
        new_process = process_watcher()
        # 4  Determines all info that we are looking for
        proc_owner = new_process.GetOwner()
        proc_owner = "%s\\%s" % (proc_owner[0], proc_owner[2])
        create_date = new_process.CreationDate
        executable = new_process.ExecutablePath
        cmdline = new_process.CommandLine
        pid = new_process.ProcessID
        parent_pid = new_process.ParentProcessId
        
        privileges = get_process_privileges(pid)
        
        process_log_message = "%s,%s,%s,%s,%s,%s,%s\r\n" % (create_date, proc_owner, executable, cmdline, pid, parent_pid, privileges)
        
        print process_log_message
        
        log_to_file(process_log_message)
        
    except:
        pass