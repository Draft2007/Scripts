# Copyright (C) 2010-2014 Immunity Inc.
# This file is part of El Jefe - http://www.immunityinc.com/products-eljefe.shtml
# See the file 'docs/LICENSE' for copying permission.
#import gc
#import inspect 
#import pdb 

import sys
import wmi
import os
import zlib
import threading
import Queue
import xmlrpclib
import base64
import hashlib
import socket
import time
import random
import pefile
import pythoncom
import win32con
import win32api
import win32security
import win32process
import inspect
import cPickle
from Crypto.Cipher import AES
import httplib
import ssl
import requests
from decimal import Decimal 

import ElJefeUtils
from ConfParser import conf_parser
from DeletionMonitor import get_parent,clean_parent_list

# debugging settings
LOGHOST = "172.16.41.1"
LOGPORT = 5555

# internal settings
ENCRYPT_KEY = "12345678901234561234567890123456"
DEFAULT_TIME_TO_WAIT = 100.0

# Global
exit_threads   = False
recv_list      = []
time_to_wait   = DEFAULT_TIME_TO_WAIT

# Get Configuration from file
conf_file_path = os.path.dirname(os.path.realpath(sys.argv[0]))   
file_path = os.path.join(conf_file_path, "config.ini")
config = conf_parser().parse(file_path)

key = os.path.join(conf_file_path, 'certs', "client.key")
cert = os.path.join(conf_file_path, 'certs', "client.pem")
ca_cert = os.path.join(conf_file_path, 'certs', "cacert.pem")
server_cert_path = os.path.join(conf_file_path, 'certs', "server.pem")


class HTTPSClientAuthConnection(httplib.HTTPSConnection):
    """ Class to make a HTTPS connection, with support for full client-based
        SSL Authentication.
    """

    def __init__(self, host, port, key_file, cert_file, ca_file, timeout=None):
        httplib.HTTPSConnection.__init__(self, host, key_file=key_file,
                                         cert_file=cert_file)
        self.key_file = key_file
        self.cert_file = cert_file
        self.ca_file = ca_file
        self.timeout = timeout

    def connect(self):
        """ Connect to a host on a given (SSL) port.
            If ca_file is pointing somewhere, use it to check Server Certificate.

            Redefined/copied and extended from httplib.py:1105 (Python 2.6.x).
            This is needed to pass cert_reqs=ssl.CERT_REQUIRED as parameter
            to ssl.wrap_socket(), which forces SSL to check server certificate
            against our client certificate.
        """
        sock = socket.create_connection((self.host, self.port), self.timeout)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()

        self.sock = ssl.wrap_socket(sock,
                                    self.key_file,
                                    self.cert_file,
                                    ca_certs=self.ca_file,
                                    cert_reqs=ssl.CERT_REQUIRED)



        server_cert = file(server_cert_path,'r').read()
        received_cert = ssl.DER_cert_to_PEM_cert(self.sock.getpeercert(True))

        if server_cert != received_cert:
            print "The server's certificate is invalid."
            raise

#
# get_file_hash - return a SHA1,SHA256 or MD5 hash of a file
#
def get_file_hash(file_path, Type="sha1"):

    try:
        fd = open(file_path, "rb")
        raw_file = fd.read()
        fd.close()

        if Type == "sha256":
            hasher = hashlib.sha256()
        elif Type == "md5":
            hasher = hashlib.md5()
        elif Type == "sha1":
            hasher = hashlib.sha1()
        else:
            return "N/A" 

        hasher.update(raw_file)
        code_hash = hasher.hexdigest()    
    except:
        code_hash = "N/A"

    return code_hash
#
# get_process_executable - returns the file path for a process ID
#
def get_process_executable(pid):
    #print "pid " + str(pid)
   
    if not pid or pid == 4:
        return None
   
    try:
        handle     = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, pid)
        executable = win32process.GetModuleFileNameEx(handle,0)
        win32api.CloseHandle(handle)
         
        if "\\SystemRoot\\".lower() in executable.lower():
            executable = None
        
        if "\\??\\" in executable:
            executable = executable.replace("\\??\\", "") 
            
    except:
        executable = None
        #print "Exception: " + str(sys.exc_info())
        

    return executable

#
# get_process_executable_by_name - returns the file path for a file name 
#
def get_process_executable_by_name(filename,cmdline=None):
    try:
        if not cmdline:
            # TODO: Check in a whitelist
            system_path = os.environ['WINDIR'] + "\\System32\\"
            full_path = system_path + filename
            #check if file exist
            #print "* " + full_path 
            if os.path.exists(full_path):
                executable = full_path
            else:
                executable = None
        else:
            if "\\SystemRoot\\".lower() in cmdline.lower():                
                os_path = os.environ['WINDIR'] 
                system_path = cmdline.replace("\\SystemRoot",os_path)[:cmdline.rfind("\\")] 
                full_path = system_path + filename
                #print full_path
                #check if file exist
                if os.path.exists(full_path):
                    executable = full_path
                else:
                    executable = None
            else:
                executable = None
    except:
        executable = None

    return executable

#
# get_code - returns a hex dump of the code section of an executable
#
def get_code(file_path):
    hexdump = ""

    try:
        pe  = pefile.PE(file_path)
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_point_offset = entry_point+pe.OPTIONAL_HEADER.ImageBase
        data = pe.get_memory_mapped_image()[entry_point:entry_point+4096]

        for i in data:            
            hexdump += "%02x" % ord(i)
		
    except:
        hexdump = "Malformed Executable"

    return hexdump

# 
# get_process_privileges - returns a list of Se* privileges enabled on a given process.
# 
def get_process_privileges(pid):
    try:
        # obtain a handle to the target process
        hproc = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION,False,pid)

        # open the main process token
        htok = win32security.OpenProcessToken(hproc,win32con.TOKEN_QUERY)

        # retrieve the list of privileges enabled
        privs = win32security.GetTokenInformation(htok, win32security.TokenPrivileges)

        # iterate over all privileges and output the ones that are enabled
        priv_list = ""
        for i in privs:
                # check if the privilege is enabled
            if i[1] == 3:
                priv_list += "%s|" % win32security.LookupPrivilegeName(None,i[0])
        
        win32api.CloseHandle(hproc)
    except:
        priv_list = "N/A"

    return priv_list

# 
# prepare_xml = prepare the XML message for the xmlrpc endpoint
# 
def prepare_process_record(new_process,owner):

    """
    From: http://msdn.microsoft.com/en-us/library/aa394372(v=vs.85).aspx

    class Win32_Process : CIM_Process
{
  string   Caption;
  string   CommandLine;
  string   CreationClassName;
  datetime CreationDate;
  string   CSCreationClassName;
  string   CSName;
  string   Description;
  string   ExecutablePath;
  uint16   ExecutionState;
  string   Handle;
  uint32   HandleCount;
  datetime InstallDate;
  uint64   KernelModeTime;
  uint32   MaximumWorkingSetSize;
  uint32   MinimumWorkingSetSize;
  string   Name;
  string   OSCreationClassName;
  string   OSName;
  uint64   OtherOperationCount;
  uint64   OtherTransferCount;
  uint32   PageFaults;
  uint32   PageFileUsage;
  uint32   ParentProcessId;
  uint32   PeakPageFileUsage;
  uint64   PeakVirtualSize;
  uint32   PeakWorkingSetSize;
  uint32   Priority = NULL;
  uint64   PrivatePageCount;
  uint32   ProcessId;
  uint32   QuotaNonPagedPoolUsage;
  uint32   QuotaPagedPoolUsage;
  uint32   QuotaPeakNonPagedPoolUsage;
  uint32   QuotaPeakPagedPoolUsage;
  uint64   ReadOperationCount;
  uint64   ReadTransferCount;
  uint32   SessionId;
  string   Status;
  datetime TerminationDate;
  uint32   ThreadCount;
  uint64   UserModeTime;
  uint64   VirtualSize;
  string   WindowsVersion;
  uint64   WorkingSetSize;
  uint64   WriteOperationCount;
  uint64   WriteTransferCount;
};"""
    
    #print "prepare_process begin"
    privilege_list = get_process_privileges(new_process.ProcessId)    
    #print new_process
    child_binary = new_process.ExecutablePath
    #print child_binary
    
    if not child_binary:
        #Tryin to obtain Executable Path with pid
        child_binary = get_process_executable(new_process.ProcessId)  
       
        #Trying again with new_process
        if not child_binary:
            child_binary = new_process.ExecutablePath

        #Trying again using only caption
        if not child_binary:
            child_binary = get_process_executable_by_name(new_process.Caption)
        
        #Trying again using caption and command line
        if not child_binary:
            if new_process.CommandLine:
                child_binary = get_process_executable_by_name(new_process.Caption,new_process.CommandLine)
        
        #Trying again using description and command line
        if not child_binary:            
            if new_process.CommandLine:
                child_binary = get_process_executable_by_name(new_process.Description,new_process.CommandLine)
    
     
    if not child_binary:
        print "Can't find child binary"
        #print new_process 
        return None
       
    code              = get_code(child_binary)               # if child binary is None the result is Malformed Executable
    #code              = "N/A"               				# if child binary is None the result is Malformed Executable
    child_hash        = get_file_hash(child_binary)          # N/A if child_binary is None
    child_hash_sha256 = get_file_hash(child_binary,"sha256") # N/A if child_binary is None
    child_hash_md5    = get_file_hash(child_binary,"md5")    # N/A if child_binary is None

    child_file_size = 0
    
    if child_binary:
        child_file_size = os.path.getsize(child_binary)
    
    #print "Find Parent"    
    #print "Code:" + code
    #print "Parent Pid " + str(new_process.ParentProcessId)
    
    parent_executable = get_process_executable(new_process.ParentProcessId)
 
    # this wins the race between the parent dying before the child
    # creation event is triggered
    if not parent_executable:
        # Check with the ParentProcessId in the deletion server
        if new_process.ParentProcessId !=4:
            print "Asking deletion list with pid %s" % str(new_process.ParentProcessId)
            # deletion list return None if the pid is not there.
            parent_executable = get_parent(new_process.ParentProcessId)
            print "result: %s" % str(parent_executable)

            
    if parent_executable:
        parent_binary      = parent_executable
        parent_code        = get_code(parent_binary)
        #parent_code   = "N/A" 
        parent_hash        = get_file_hash(parent_binary)
        parent_hash_sha256 = get_file_hash(parent_binary,"sha256")
        parent_hash_md5    = get_file_hash(parent_binary,"md5")
        
        hasher = hashlib.sha1()
        hasher.update(parent_code)
        parent_code_hash = hasher.hexdigest()
        parent_file_size = os.path.getsize(parent_binary)
    else:
        parent_binary        = "N/A"
        parent_code          = "N/A"
        parent_hash          = "N/A"
        parent_hash_sha256   = "N/A"
        parent_hash_md5      = "N/A"
        parent_code_hash     = "N/A"
        parent_file_size     = -1

    # Hash the code section
    hasher = hashlib.sha1()
    hasher.update(code)
    code_hash = hasher.hexdigest()
	
    # get the process owner information
    username = owner[2]
    group    = owner[0]

    process_record = {}
    process_record['event_date']                        = new_process.CreationDate
    process_record['parent_binary']                     = parent_binary 
    process_record['parent_hash']                       = parent_hash
    process_record['parent_hash_sha256']                = parent_hash_sha256
    process_record['parent_hash_md5']                   = parent_hash_md5
    process_record['child_binary']                      = child_binary 
    process_record['child_hash']                        = child_hash
    process_record['child_hash_sha256']                 = child_hash_sha256
    process_record['child_hash_md5']                    = child_hash_md5
    process_record['user']                              = "%s\\%s" % (group,username)
    process_record['station']                           = socket.gethostname()
    process_record['code_hash']                         = code_hash
    process_record['code']                              = code
    process_record['privileges']                        = privilege_list
    process_record['parent_code']                       = parent_code
    process_record['parent_code_hash']                  = parent_code_hash
    process_record['parent_pid']                        = new_process.ParentProcessId 
    process_record['child_pid']                         = new_process.ProcessId 
    process_record['parent_file_size']                  = parent_file_size
    process_record['child_file_size']                   = child_file_size
    process_record['commandline']                       = new_process.CommandLine if new_process.CommandLine else "N/A"  
    process_record['flags']                             = "N/A"
    process_record['arch']                              = ElJefeUtils.get_pe_arch(child_binary) 
    process_record['creation_class_name']               = new_process.CreationClassName if new_process.CreationClassName else "N/A" 
    process_record['cs_creation_class_name']            = new_process.CSCreationClassName if new_process.CSCreationClassName else "N/A" 
    process_record['cs_name']                           = new_process.CSName if new_process.CSName else "N/A"  
    process_record['handle']                            = new_process.Handle if new_process.Handle else "N/A" 
    process_record['handle_count']                      = new_process.HandleCount if new_process.HandleCount else "N/A" 
    process_record['kernel_mode_time']                  = new_process.KernelModeTime if new_process.KernelModeTime else "N/A" 
    process_record['user_mode_time']                    = new_process.UserModeTime if new_process.UserModeTime else "N/A"
    process_record['working_set_size']                  = new_process.WorkingSetSize if new_process.WorkingSetSize else "N/A"
    process_record['max_working_set_size']              = new_process.MaximumWorkingSetSize if new_process.MaximumWorkingSetSize else "N/A" 
    process_record['min_working_set_size']              = new_process.MinimumWorkingSetSize if new_process.MinimumWorkingSetSize else "N/A" 
    process_record['os_creation_class_name']            = new_process.OSCreationClassName if new_process.OSCreationClassName else "N/A" 
    process_record['os_name']                           = new_process.OSName if new_process.OSName else "N/A" 
    process_record['windows_version']                   = new_process.WindowsVersion if new_process.WindowsVersion else "N/A"
    process_record['other_operation_count']             = new_process.OtherOperationCount if new_process.OtherOperationCount else "N/A"  
    process_record['other_transfer_count']              = new_process.OtherTransferCount if new_process.OtherTransferCount else "N/A"
    process_record['page_faults']                       = new_process.PageFaults if new_process.PageFaults else "N/A"
    process_record['page_file_usage']                   = new_process.PageFileUsage if new_process.PageFileUsage else "N/A"
    process_record['peak_page_file_usage']              = new_process.PeakPageFileUsage if new_process.PeakPageFileUsage else "N/A"
    process_record['peak_virtual_size']                 = new_process.PeakVirtualSize if new_process.PeakVirtualSize else "N/A"
    process_record['peak_working_set_size']             = new_process.PeakWorkingSetSize if new_process.PeakWorkingSetSize else "N/A"
    process_record['priority']                          = new_process.Priority if new_process.Priority else "N/A"
    process_record['private_page_count']                = new_process.PrivatePageCount if new_process.PrivatePageCount else "N/A"
    process_record['quota_non_paged_pool_usage']        = new_process.QuotaNonPagedPoolUsage if new_process.QuotaNonPagedPoolUsage else "N/A"
    process_record['quota_paged_pool_usage']            = new_process.QuotaPagedPoolUsage if new_process.QuotaPagedPoolUsage else "N/A"
    process_record['quota_peak_non_paged_pool_usage']   = new_process.QuotaPeakNonPagedPoolUsage if new_process.QuotaPeakNonPagedPoolUsage else "N/A"
    process_record['quota_peak_paged_pool_usage']       = new_process.QuotaPeakPagedPoolUsage if new_process.QuotaPeakPagedPoolUsage else "N/A"
    process_record['read_operation_count']              = new_process.ReadOperationCount if new_process.ReadOperationCount else "N/A"
    process_record['read_transfer_count']               = new_process.ReadTransferCount if new_process.ReadTransferCount else "N/A"
    process_record['write_operation_count']             = new_process.WriteOperationCount if new_process.WriteOperationCount else "N/A"
    process_record['write_transfer_count']              = new_process.WriteTransferCount if new_process.WriteTransferCount else "N/A"
    process_record['session_id']                        = new_process.SessionId if new_process.SessionId else "N/A"
    process_record['thread_count']                      = new_process.ThreadCount if new_process.ThreadCount else "N/A"
    process_record['virtual_size']                      = new_process.VirtualSize if new_process.VirtualSize else "N/A"

    #if not new_process.CommandLine:
    #    print "***" + str(process_record)
    
    return process_record

def send_process_record(new_process,owner):
    
    # send the information off to the XML server
    try:
        process_record = prepare_process_record(new_process,owner) 
        #print process_record
        send_eljefe_message(process_record)
    except:
        print "Exception: " + str(sys.exc_info())
        #print process_record
        raise
        return

#
# Send the process event off to our logging server. 
#
def send_eljefe_message(process_record):

    global config
    log_host = config.get('host')
    log_port = int(config.get('port'))

    try:
        trans = auth_transport(key, cert, ca_cert)
        print "send_eljefe_message():Trying to send to: %s:%d" % (log_host,log_port)
        server = xmlrpclib.Server('https://%s:%s' % (log_host,log_port),transport = trans)
        
        try:
            infile = open('messages.pkl', 'rb')
            datalist = cPickle.load(infile)
            infile.close()
        except:
            datalist = []

        for record in datalist:
            try:
                result = server.process_created(record)
                datalist.remove(record)
            except:
                break # stop the list in its current state

        response = server.process_created(process_record)
        print "Message sent!"

        #Analize the response from server
        #print response
        recv_eljefe_message(response)

    except xmlrpclib.ProtocolError, err:

        try:
            infile = open('messages.pkl', 'rb')
            datalist = cPickle.load(infile)
            infile.close()
        except:
            datalist = []

        try:
            datalist.append(process_record)
            outfile = open('messages.pkl', 'ab')
            cPickle.dump(datalist, outfile)
            outfile.close()
        except:
            print "Failed to store process record to pickle"
            print "A protocol error occurred"
            print "URL: %s" % err.url
            print "HTTP/HTTPS headers: %s" % err.headers
            print "Error code: %d" % err.errcode
            print "Error message: %s" % err.errmsg
            raise

#
# Receive the response from server. 
#
def recv_eljefe_message(response):

    if not response:
        return

    # if response is already sent should be on this list    
    if response not in recv_list and response != '': 
        # check if response's items are already on the list
        for item in response:
            for binary_list in recv_list:
                if item in binary_list:
                    # if the item is on the list is  
                    # because it's been processing now 
                    response.remove(item)

        # adding to the list    
        recv_list.append(response)

        # collect binaries to send
        binaries= []  
        for path in response:
            print "Request for: " + path
            try:
                with open(path, "rb") as handle:
                    binary_data = xmlrpclib.Binary(handle.read())
            except Exception as e:
                message = e.strerror 
                print message
                binary_data = message

            binary_tuple = ( path , binary_data )
            binaries.append(binary_tuple)

        send_binary(binaries)
        recv_list.remove(response)


def send_binary(binaries,):

    global config
    log_host = config.get('host')
    log_port = int(config.get('port'))

    try:
        trans = auth_transport(key, cert, ca_cert)
        print "Trying to send binary to: %s:%d" % (log_host,log_port)
        server = xmlrpclib.Server('https://%s:%s' % (log_host,log_port),transport = trans)
        server.upload_files(binaries,socket.gethostname())
    except:
        raise


#
# This function monitors new process creation and handles sending
# the information off to the XML server.
#
class creation_monitor(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.setDaemon(True)

    def run(self):
        global exit_threads

        print "Starting Creation monitor"
        pythoncom.CoInitialize()

        # instantiate the WMI interface
        c = wmi.WMI()

        # create our process monitor
        process_monitor = c.Win32_Process.watch_for("creation")

        while not exit_threads:
            try:
                new_process = process_monitor()

                try:
                    owner       = new_process.GetOwner()
                except:
                    owner       = ("Unknown","Unknown","Unknown")
                #print new_process
                #t = threading.Thread(target=prepare_process_record,args=(new_process,owner))		
                t = threading.Thread(target=send_process_record,args=(new_process,owner))		
                t.start()

            except KeyboardInterrupt:
                exit_threads = True
                raise
            except:		
                print "CreationMonitor - Exception: " + str(sys.exc_info())
                raise

        pythoncom.CoUninitialize ()

#
# This function monitors the all running process and handles sending
# the information off to the XML server.
#

class process_monitor(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.setDaemon(True)

    def run(self):
        global exit_threads
        global time_to_wait 
		
        print "Starting Process monitor"
		# First thing is send the running process
        #send_processes_list()
        #time_to_wait = 1
        count = 0
        while not exit_threads:
            try:
                #t0= time.clock()
                # This is for avoiding a time drift.        
                #next_call = next_call + time_to_wait
                #print "next call " + str(next_call)
                #print "time " + str(time.time())
                #print "result " + str(next_call - time.time())
                #nt = threading.Timer( next_call - time.time(), send_processes_list )
                #nt = threading.Timer( time_to_wait, send_processes_list )
                send_processes_list()
                time.sleep(time_to_wait)
                
                #TODO: Improve this
                #count+=1
                #if count == 1000:
                #    clean_parent_list()
                ######################
                
                #nt = threading.Thread( target=send_processes_list )
                #print "Starting thread"
                #nt.start()
                #print "join thread"               
                #nt.join()              
                #t= time.clock() - t0
                #print "time" + str(t)
				
            except KeyboardInterrupt:                
                exit_threads = True
                #print "pase por aca"
                raise
            except:
                #print "2 pase por aca"
                print "ProcessMonitor - Exception: " + str(sys.exc_info())
                raise
        
        
class auth_transport(xmlrpclib.SafeTransport):

    def __init__(self, key_file, cert_file, ca_file):
        global config
        self.user = config.get('user')
        self.password = config.get('password')
        self.https_proxy = config.get('https_proxy')
        self.__cert_file = cert_file
        self.__key_file = key_file
        self.__ca_file = ca_file

        xmlrpclib.Transport.__init__(self)


    def single_request(self, host, handler, request_body, verbose=0):
        if self.https_proxy:
            proxy_dict = {'https': self.https_proxy}
        else:
            proxy_dict = None

        # Authentication stuff
        data = self.user 
        data+= ":"
        data+= self.password

        # padding
        while ((len(data) % 16) != 0):
            data += "#"

        iv = os.urandom(16)
        #print iv
        obj = AES.new(ENCRYPT_KEY, AES.MODE_CBC, iv)
        enc_data = obj.encrypt(data)

        token = iv
        token+=enc_data

        # base64 encoded
        b64_token = base64.b64encode(token)
        headers = {'Authorization': b64_token,
                   "Content-Type" : "text/xml",
                   "Content-Length" : str(len(request_body))
                   }

        r = requests.post('https://%s%s' % (host, handler), 
                          verify = self.__ca_file,
                          cert = ( self.__cert_file , self.__key_file),
                          proxies = proxy_dict,
                          data = request_body,
                          headers = headers)

        if r.status_code != 200:
            print r.text
            return ''

        # We need to convert the XML data into a python object                            
        p, u = self.getparser()
        p.feed(r.text)
        p.close()
        return u.close()

        
def send_processes_list():
    """
    This function will be called forever every X amount of time to send
    the station process list to the server.
    """
    global config
 
    log_host = config.get('host')
    log_port = int(config.get('port'))
    
    response = 0
    trans = auth_transport(key, cert, ca_cert)
    print "send_processes_list():Trying to send processes to: %s:%d" % (log_host,log_port)
    try:
        server = xmlrpclib.Server('https://%s:%s' % (log_host,log_port),transport = trans)        
        response = server.save_processes(get_processes())
    except KeyboardInterrupt:
        exit_threads = True
        raise
    except:
        #print "Exception: " + str(sys.exc_info())
        raise
    
    if response:
        #print "received time to wait" + str(response) 
        update_time_to_wait(Decimal(response))
		
def update_time_to_wait(new_time):
    global time_to_wait
    if time_to_wait != new_time:
        time_to_wait = new_time
        print "Time to wait for scanning processes was updated. New time : %s" % str(new_time)
    
    
def get_processes():
    pythoncom.CoInitialize()
    c = wmi.WMI ()
    processes = [] 

    for process in c.Win32_Process():
        #print process.ProcessId, process.Name
        
        try:
                owner = process.GetOwner()
        except:
                owner = ("Unknown","Unknown","Unknown")
               
        if process.ProcessId == 0 or process.ProcessId == 4:
            #print process
            continue
    
        record = prepare_process_record(process,owner)
         
        if record:
            processes.append(record)
        
    pythoncom.CoUninitialize ()
    return processes

if __name__ == '__main__':
    
    creation_monitor().start()
    process_monitor().start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        exit_threads = True
        print "Exiting"
        exit(0)
