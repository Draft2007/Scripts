# Copyright (C) 2010-2014 Immunity Inc.
# This file is part of El Jefe - http://www.immunityinc.com/products-eljefe.shtml
# See the file 'docs/LICENSE' for copying permission.

## UDP server to process the incoming data and jam it into the PG database

import zlib
import struct
import threading
import psycopg2
import binascii
import time
import xmlrpclib
import SimpleXMLRPCServer
import os
import datetime
import time
import traceback
import sys
import math
import base64
import cPickle
import SocketServer
import BaseHTTPServer
import SimpleHTTPServer
import socket
import ssl
import email
import smtplib
from email.mime.text import MIMEText
from django.core.mail import send_mail
from Crypto.Cipher import AES
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
from alerts.models import *

#import cuckoo settings
import webapp
from webapp.settings import PROJECT_ROOT

if webapp.settings.CUCKOO_FOUND:
    from webapp.settings import CUCKOO_PATH
    sys.path.append(CUCKOO_PATH)
    from lib.cuckoo.core.database import Database

#ElJefe imports
#import ElJefeXMLServerDb
from ElJefeXMLServerDb import *
import ElJefeUtils

ENCRYPT_KEY = "12345678901234561234567890123456"

class ElJefeRPC:
    """
    The primary class with El Jefe functions.
    """

    def __init__(self):
        self.uppriv_logger = uppriv_database()
        

    #
    # This processes any new process creation events
    # process_data is a dictionary with the following fields
    #
    # event_date                         = process creation date
    # parent_binary                      = the parent binary path
    # parent_hash                        = SHA1 hash of the parent binary
    # parent_hash_sha256                 = SHA256 hash of the parent binary
    # parent_hash_md5                    = MD5 of the parent binary
    # child_binary                       = the path of the created binary
    # child_hash                         = SHA1 hash of the child binary
    # child_hash_sha256                  = SHA256 hash of the child binary
    # child_hash_md5                     = md5 hash of the child binary
    # user                               = the user that created the process
    # station                            = the computer hostname generating the event
    # code_hash                          = SHA1 hash of the binary's .text section
    # code                               = hexdump of the first page of code from the .text
    # privileges                         = pipe delimited list of Se* privileges
    # parent_code                        = hexdump of the first page of the parent's .text
    # parent_code_hash                   = SHA1 hash of the parent's .text section
    # parent_pid                         = the PID of the parent process
    # child_pid                          = the PID of the created process
    # parent_file_size                   = the size of the parent binary on disk
    # child_file_size                    = the size of the child bianry on disk
    # commandline                        = commandline parameters passed to created process
    # flags                              = process creation flags currently set to N/A
    # arch                               = whether the architecture is 32/64 bit
    # creation_class_name                = first concrete class that is used to create an instance
    # cs_creation_class_name             = creation class name of the scoping computer system
    # cs_name                            = scoping computer system
    # handle                             = process identifier
    # handle_count                       = total number of open handles owned by the process
    # kernel_mode_time                   = time in kernel mode
    # user_mode_time                     = time un user mode
    # working_set_size                   = amount of memory in bytes that a process needs to execute efficiently
    # max_working_set_size               = maximum set of memory pages visible to the process
    # min_working_set_size               = minimum set of memory pages visible to the process
    # os_creation_class_name             = creation class name for the scoping os
    # os_name                            = name of the os
    # windows_version                    = version of Windows in which the process is running
    # other_operation_count              = number of I/O operations performed (not read/write)
    # other_transfer_count               = amount of data transferred during operations (not read/write)
    # page_faults                        = number of page faults that a process generates
    # page_file_usage                    = amount of page file space that a process is using currently
    # peak_page_file_usage               = maximum amount of page file space used during the life of a process
    # peak_virtual_size	                 = maximum virtual address space a process uses at any one time.
    # peak_working_set_size              = peak working set size of a process
    # priority                           = scheduling priority of a process within an operating system (range [lowest:0 to highest:31])
    # private_page_count                 = number of pages allocated that are only accessible to the process
    # quota_non_paged_pool_usage         = quota amount of nonpaged pool usage for a process
    # quota_paged_pool_usage             = quota amount of paged pool usage for a process
    # quota_peak_non_paged_pool_usage    = peak quota amount of nonpaged pool usage for a process
    # quota_peak_paged_pool_usagei       = peak quota amount of paged pool usage for a process
    # read_operation_count               = number of read operations performed
    # read_transfer_count                = amount of data read
    # write_operation_count              = number of write operations performed
    # write_transfer_count	         = amount of data written
    # session_id                         = unique identifier that an operating system generates when a session is created
    # thread_count                       = number of active threads in a process
    # virtual_size                       = current size of the virtual address space that a process is using

    def process_created(self, process_data, ip_address, certificate):
        logging.info("[*] Processing data")
        xmllog = "=" * 40
        #xmllog+= "\n%s\n" % remote_host
        xmllog += str(process_data)
        xmllog += "\n" + "=" * 40 + "\n"
        #remote_host = ""

        self.uppriv_logger.configure(process_data, ip_address, certificate)
        try:
            event = self.uppriv_logger.store_uppriv_event()
        except KeyboardInterrupt:
            raise            
        except Exception, e:
            traceback.print_exc()
            logging.exception(e)
        
        station = stations.objects.get(hostname=process_data['station'])
        bins = binary_requests.objects.filter(binary__station=station)
        bins_paths = [bin.binary.file_path for bin in bins]
        #print bins_paths
        if bins_paths:
            logging.info('The following files have been added for download:')
            for elem in bins_paths:
                logging.info(elem)

        logging.info("[*] Finished.")
        return bins_paths

    def upload_files(self, bins, station):
        print 'Uploading'
        logging.info("[*] Uploading files")
        for binary in bins:
            binary_path, binary_data = binary

            logging.info("  [+] Uploading : " + binary_path)
            bin = binaries.objects.get(file_path=binary_path, station=station)

                # If binary_data is a string
                # then It will be an error
            if isinstance(binary_data, str):
                bin.data = binary_data
            else:
                bin.data = binary_data.data

            bin.save()

            bin_to_del = binary_requests.objects.get(binary__file_path=binary_path,
                                                     binary__station=station)
            bin_to_del.delete()
        logging.info("[*] Upload finished")
        logging.info("[*] Done")
        print 'done'
        
    def save_processes(self, processes, ip_address, certificate):
        response = None
        logging.info("[*] Save running processes")

        log_date = datetime.datetime.now() 
        
        for process in processes:
            #print process["child_binary"] + " " + str(process["child_pid"]) 
            self.uppriv_logger.configure(process, ip_address, certificate,log_date)
        
            try:
                self.uppriv_logger.store_uppriv_process()
            except KeyboardInterrupt:
                raise                
            except Exception, e:
                logging.exception(e)
                return response
        
        logging.info("[*] Finished.")
        
        # delete missing processes
        objects = running_processes.objects.extra(where=['log_date!=%s'], params=[log_date])
        objects.delete()
        #print "*************"
        #for o in objects:
        #    print str(o.binary) + " " + str(o.pid)
        #running_process.objects.filter(log_date != log_date).delete()

        try: 
            station_name = processes[0]['station'] 
            # get station for send the scanning time to the client       
            station = stations.objects.get(hostname=station_name)
            response = str(station.scanning_time)
        except KeyboardInterrupt:
            raise            
        except Exception, e:
            logging.exception(e)
        
        return response 
    
    #ADD Dictionary details

    def save_usb_record(self, data, ip_address, certificate):
        logging.info("[*] Processing USB Data")

        self.uppriv_logger.configure(data, ip_address, certificate)
        try:
            usb_event = self.uppriv_logger.store_uppriv_usb_event()
        except KeyboardInterrupt:
            raise            
        except Exception, e:
            traceback.print_exc()
            logging.exception(e)
        
        logging.info("[*] Finished.")
        return 'done' 
    
    def save_usb_mass_storage_record(self, data, ip_address, certificate):
        logging.info("[*] Processing USB Mass Storage Data")

        self.uppriv_logger.configure(data, ip_address, certificate)
        try:
            usb_event = self.uppriv_logger.store_uppriv_usb_mass_storage_event()
        except KeyboardInterrupt:
            raise            
        except Exception, e:
            traceback.print_exc()
            logging.exception(e)
        
        logging.info("[*] Finished.")
        return 'done' 


class SecureXMLRPCServer(BaseHTTPServer.HTTPServer,SimpleXMLRPCServer.SimpleXMLRPCDispatcher):
    def __init__(self, server_address, HandlerClass,logRequests=False):
        """Secure XML-RPC server.
        It it very similar to SimpleXMLRPCServer but it uses HTTPS for transporting XML data.
        """
        self.logRequests = logRequests
        try:
            SimpleXMLRPCServer.SimpleXMLRPCDispatcher.__init__(self,
                                                               allow_none=True)
        except TypeError:
            # An exception is raised in Python 2.5 as the prototype of the __init__
            # method has changed and now has 3 arguments (self, allow_none, encoding)
            #
            SimpleXMLRPCServer.SimpleXMLRPCDispatcher.__init__(self, True, None)

        SocketServer.BaseServer.__init__(self, server_address, HandlerClass)

        self.socket = ssl.wrap_socket(socket.socket(), 
                                      server_side=True, 
                                      certfile=CERTFILE,
                                      keyfile=KEYFILE, 
                                      ssl_version=ssl.PROTOCOL_SSLv23,
                                      ca_certs=CA_CERTFILE,
                                      cert_reqs=ssl.CERT_REQUIRED)


        self.server_bind()
        self.server_activate()

class SecureXMLRPCRequestHandler(SimpleXMLRPCServer.SimpleXMLRPCRequestHandler): 

    def _dispatch(self,method,process_data, asd = None):
        rpc = ElJefeRPC()

        if method: 
            ip_address = self.request.getpeername()[0]
            certificate = ssl.DER_cert_to_PEM_cert(self.request.getpeercert(True))	    		

        if method == "process_created":
            try:
                station = stations.objects.get(hostname = process_data[0]['station'])
                
                self.check_client_certificate(station.certificate,certificate, ip_address)
                
            except ObjectDoesNotExist:
                pass

            return rpc.process_created(process_data[0],
                                       ip_address,
                                       certificate)

        if method == "upload_files":
            try: 
                station = stations.objects.get(hostname = process_data[1])
                
                self.check_client_certificate(station.certificate,certificate, ip_address)
                
            except ObjectDoesNotExist:
                pass
            
            return rpc.upload_files(process_data[0], station)

        if method == "save_processes":
            try:
                station = stations.objects.get(hostname = process_data[0][0]['station'])
                
                self.check_client_certificate(station.certificate,certificate, ip_address)

            except ObjectDoesNotExist:
                pass
            return rpc.save_processes(process_data[0], ip_address, 
                                      certificate)

        if method == "save_usb_record":
            try:
                station = stations.objects.get(hostname = process_data[0]['station'])
                
                self.check_client_certificate(station.certificate,certificate, ip_address)
                
            except ObjectDoesNotExist:
                pass

            return rpc.save_usb_record(process_data[0],
                                       ip_address,
                                       certificate)

        if method == "save_usb_mass_storage_record":
            try:
                station = stations.objects.get(hostname = process_data[0]['station'])
                
                self.check_client_certificate(station.certificate,certificate, ip_address)
                
            except ObjectDoesNotExist:
                pass

            return rpc.save_usb_mass_storage_record(process_data[0],
                                       ip_address,
                                       certificate)



    def check_client_certificate(self,station_cert, certificate, ip_address):
        if station_cert != certificate:
            # This exception is sent to the client, the server is only 
            # printing the following msg
            logging.info("[*] Client's certificate is invalid, aborting connection with client %s " % ip_address)
            raise Exception("Certificate is invalid, check client.pem inside your certs folder")


    def setup(self):
        self.connection = self.request
        self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
        self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)

    def report_401(self):
        # Report a 401 error
        self.send_response(401)
        response = 'Authentication required.'
        self.send_header("Content-type", "text/plain")
        self.send_header("Content-length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def do_POST(self):
        """Handles the HTTPS POST request.

        It was copied out from SimpleXMLRPCServer.py and modified to shutdown the socket cleanly.
        """
        if not self.authenticate():
            tbfile = open('error.log', 'ab')
            tbfile.write("Authentication Failed\n Sending 401 message to client")
            tbfile.close()	
            self.report_401()

        else:
            try:
                # get arguments
                data = self.rfile.read(int(self.headers["content-length"]))
                # In previous versions of SimpleXMLRPCServer, _dispatch
                # could be overridden in this class, instead of in
                # SimpleXMLRPCDispatcher. To maintain backwards compatibility,
                # check to see if a subclass implements _dispatch and dispatch
                # using that method if present.
                response = self.server._marshaled_dispatch(
                    data, getattr(self, '_dispatch', None)
                )		

                #print data
            except KeyboardInterrupt:
                raise                
            except: # This should only happen if the module is buggy
                # internal error, report as HTTP server error
                self.send_response(500)
                self.end_headers()
                tbfile = open('error.log', 'ab')
                traceback.print_exc(file=tbfile)
                tbfile.close()	
            else:
                # got a valid XML RPC response
                self.send_response(200)
                self.send_header("Content-type", "text/xml")
                self.send_header("Content-length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

                # shut down the connection
                self.wfile.flush()

                #modified as of http://docs.python.org/library/ssl.html
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()

    def authenticate(self):

        self.validuser = False
        enc_data = None
        b64_enc_data = None

        # handle authentication
        if self.headers.has_key('Authorization'):
            b64_enc_data = self.headers.getheader('Authorization')

        if not b64_enc_data:
            tbfile = open('error.log', 'ab')
            tbfile.write("Authorization header is missing in request\n")
            tbfile.close()	
            return False

        enc_data = base64.b64decode(b64_enc_data)
        iv  = enc_data[:16]
        data = enc_data[16:]
        try:
            obj = AES.new(ENCRYPT_KEY, AES.MODE_CBC, iv)
        except KeyboardInterrupt:
            raise            
        except:
            tbfile = open('error.log', 'ab')
            traceback.print_exc(file=tbfile)
            tbfile.close()	

        try:
            dec_data  = obj.decrypt(data)
        except KeyboardInterrupt:
            raise
        except:
            tbfile = open('error.log', 'ab')
            tbfile.write("Error while decrypting token\n")
            traceback.print_exc(file=tbfile)
            tbfile.close()	
            return False

        #remove padding
        data = ""
        if dec_data.find('#') != -1 :
            data = dec_data[:dec_data.find('#')]
        else :
            data = dec_data

        user = data[:data.find(':')]
        pwd  = data[data.find(':')+1:]

        if checkXMLUser(user,pwd):
            self.validuser = True

        return self.validuser


def start_server(HandlerClass = SecureXMLRPCRequestHandler,ServerClass = SecureXMLRPCServer):
    """xml rpc over https server"""

    server_address = (LOGHOST,LOGPORT) 
    server = ServerClass(server_address, HandlerClass)    
    sa = server.socket.getsockname()
    print "[*] Serving HTTPS on", sa[0], "port", sa[1]
    server.serve_forever()	    

if __name__ == '__main__':
    # Checking if the user is running the server from the right directory
    cwd = os.getcwd().split('/')[-1]
    if cwd != 'xmlserver':
        print '[*] You have to run ElJefeXmlServer from inside the webapp/xmlserver folder'
        print '[*] Exiting'	    
        sys.exit(1)    

    cert_path = os.path.join(PROJECT_ROOT, '..' , 'xmlserver', 'certs')
    cacart_path = os.path.join(cert_path, 'cacert.pem')

    if not os.path.isfile(cacart_path):
        logging.info('[*] Certificates not found on certs folder. Generating certificates')
        cakey = createKeyPair(TYPE_RSA, 2048)
        careq = createCertRequest(cakey, CN='KR Server Authority', C='BL', L='BL', O='BLABLA', OU='BLABLA', ST='BL', emailAddress='bla@bla.com')
        cacert = createCertificate(careq, (careq, cakey), 0, (0, 60*60*24*365*5))


        # Save CA certificate
        fd = open(os.path.join(cert_path,'cacert.pem'), 'w')
        data = crypto.dump_certificate(crypto.FILETYPE_PEM, cacert)
        fd.write(data)


        # Save CA private key
        fd = open(os.path.join(cert_path,'cacert.key'), 'w')
        data = crypto.dump_privatekey(crypto.FILETYPE_PEM, cakey)
        fd.write(data)


        ########################## Create Server Cert #################################

        fname = "ElJefeXMLServer"
        cname = LOGHOST # this should match the server addr

        pkey = createKeyPair(TYPE_RSA, 2048)
        req = createCertRequest(pkey, CN=cname)
        cert = createCertificate(req, (cacert, cakey), 2, (0, 60*60*24*365*5))

        # Save private Key
        fd = open(os.path.join(cert_path,'server.key'), 'w')
        data = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
        fd.write(data)
        fd.close()

        # Save certificate
        fd = open(os.path.join(cert_path,'server.pem'), 'w')
        data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        fd.write(data)
        fd.close()    

    if len(privileges.objects.all()) == 0:
        # Create some possible privileges
        for priv in privilegesdict:
            privilege = privileges()
            privilege.name = priv
            privilege.desc = privilegesdict["%s"%priv]
            privilege.save()

    print "[*] Starting server...."
    try:
        start_server()
    except KeyboardInterrupt:
        print "[*] Exiting"
        exit(0)
    except:
        raise
