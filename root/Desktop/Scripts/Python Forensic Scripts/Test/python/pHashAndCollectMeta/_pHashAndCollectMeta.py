#
# pfish support functions, where all the real work gets done
#

# Display Message()     ParseCommandLine()      WalkPath()
# HashFile()            class_CVSWriter
# ValidateDirectory()   ValidateDirectoryWritable()
#
import os		#Python Standard Library - Miscellaneous operating system interfaces
import stat		#Python Standard Library - functions for interpreting os results
import time		#Python Standard Library - Time access and conversions functions
import hashlib		#Python Standard Library - Secure hashes and message digests
import argparse		#Python Standard Library - Parser for command line options, arguments
import csv		#Python Standard Library - reader and writer for csv files
import logging		#Python Standard Library - logging facility

log = logging.getLogger('main._pfish')
#
# Name: ParseCommand() Function
# 
# Desc: Process and Validate the command line arguments
#	use Python Standard Library module argparse
#
# Input: none
# 
# Actions:
#		Uses the standard library argparse to process the
#		command line
#		establishes a global variable gl_args where any of the
#		functions can obtain argument information
#    

def ParseCommandLine():
    parser = argparse.ArgumentParser('Python file system hashing .. p-fish')
    parser.add_argument('-v','--verbose',help ='allows progress messages to be displayed', action='store_true')        
    # Setup a group where the selection is mutually exclusive and required
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--md5',help ='specifies MD5 algorithm',action='store_true')
    group.add_argument('--sha256',help ='specifies SHA256 algorithm',action='store_true')
    group.add_argument('--sha512',help ='specifies SHA512 algorithm',action='store_true')
    parser.add_argument('-d','--rootPath',type =ValidateDirectory,required=True,help="specify the root path for hashing")
    parser.add_argument('-r','--reportPath',type =ValidateDirectoryWritable,required=True,help="specify the path for reports and logs will be written to")
    # Create a global object to hold the validated arguments,
    # these will be available then to all the Functions within
    # the _pfish.py module
    global gl_args
    global gl_hashType
    gl_args = parser.parse_args()
    if gl_args.md5:
        gl_hashType = 'MD5'
    elif gl_args.sha256:
        gl_hashType = 'SHA256'
    elif gl_args.sha512:
        gl_hashType = 'SHA512'
    else:
        gl_hashType = "Unknown"
        logging.error('Unknown Hash Type Specified')
    DisplayMessage("Command line processed: Successfully")
    return

def ValidateDirectory(theDir):
    # Validate the path is a directory
    if not os.path.isdir(theDir):
        raise argparse.ArgumentTypeError('Directory does not exist')
    # Validate the path is readable
    if os.access(theDir, os.R_OK):
        return theDir
    else:
        raise argparse.ArgumentTypeError('Directory is not readable')

def ValidateDirectoryWritable(theDir):
    # Validate the path is a directory
    if not os.path.isdir(theDir):
        raise argparse.ArgumentTypeError('Directory does not exist')
    # Validate the path is writable
    if os.access(theDir, os.W_OK):
        return theDir
    else:
        raise argparse.ArgumentTypeError('Directory is not writable')

def WalkPath():
    processCount = 0
    errorCount = 0
    log.info('Root Path:'+gl_args.rootPath)
    oCVS = _CSVWriter(gl_args.reportPath+'fileSystemReport.csv',gl_hashType)
    # Create a loop that process all the files starting
    # at the rootPath, all sub-directories will also be 
    # processed
    for root, dirs, files in os.walk(gl_args.rootPath):
        # for each file obtain the filename and call the
        # HashFile Function
        for file in files:
            fname = os.path.join(root, file)
            result = HashFile(fname, file, oCVS)
            # if successful then increment ProcessCount
            if result is True:
                processCount += 1
            # if not successful, then increment the ErrorCount
            else:
                errorCount += 1
    oCVS.writerClose()
    return(processCount)

def DisplayMessage(msg):
    if gl_args.verbose:
        print(msg)
        return
        
def HashFile(theFile, simpleName, o_result):
    # Verify that the path is valid
    if os.path.exists(theFile):
        # Verify that the path is not a symbolic link
        if not os.path.islink(theFile):
            # Verify that the file is real
            if os.path.isfile(theFile):
                try:
                    # Attempt to open the file
                    f = open(theFile, 'rb')
                except IOError:
                    # if open fails report the error
                    log.warning('Open Failed:'+ theFile)
                    return
                else:
                    try:
                        # Attempt to read the file
                        rd = f.read()
                    except IOError:
                        # if read fails, then close the file and
                        # report error
                        f.close()
                        log.warning('Read Failed:'+ theFile)
                        return
                    else:
                        # success the file is open and we can
                        # read from it
                        # lets query the file stats
                        theFileStats = os.stat(theFile)
                        (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(theFile)
                        # Display progress to the user
                        DisplayMessage("Processing File: " + theFile)
                        # convert the file size to a string
                        fileSize = str(size)
                        # convert the MAC Times to strings
                        modifiedTime = time.ctime(mtime)
                        accessTime = time.ctime(atime)
                        createdTime = time.ctime(ctime)
                        # convert the owner, group and file mode
                        ownerID = str(uid)
                        groupID = str(gid)
                        fileMode = bin(mode)
                        # process the file hashes
                        if gl_args.md5:
                            # Calculate the MD5
                            hash = hashlib.md5()
                            hash.update(rd)
                            hexMD5 = hash.hexdigest()
                            hashValue = hexMD5.upper()
                        elif gl_args.sha256:
                            # Calculate the SHA256
                            hash = hashlib.sha256()
                            hash.update(rd)
                            hexSHA256 = hash.hexdigest()
                            hashValue = hexSHA256.upper()
                        elif gl_args.sha512:
                            # Calculate the SHA512
                            hash = hashlib.sha512()
                            hash.update(rd)
                            hexSHA512 = hash.hexdigest()
                            hashValue = hexSHA512.upper()
                        else:
                            log.error('Hash not Selected')
                        # File processing completed
                        # Close the Active File
                        print("============================")
                        f.close()
                        # write one row to the output file
                        o_result.writeCSVRow(simpleName, theFile, fileSize, modifiedTime, accessTime, createdTime, hashValue, ownerID, groupID, mode)
                        return True
            else:
                log.warning('['+ repr(simpleName) +', Skipped Not a File'+']')
                return False
        else:
            log.warning('['+ repr(simpleName) +', Skipped Link NOT a File'+']')
            return False
    else:
        log.warning('['+ repr(simpleName) +', Skipped Link NOT a File'+']')
        return False
    
class _CSVWriter:
    def __init__(self, fileName, hashType):
        try:
            # create a writer object and write the header row
            self.csvFile = open(fileName, 'wb')
            self.writer = csv.writer(self.csvFile, delimiter=',', quoting=csv.QUOTE_ALL)
            self.writer.writerow( ('File', 'Path', 'Size', 'Modified Time', 'Access Time', 'Created Time', hashType, 'Owner', 'Group', 'Mode') )
        except:
            log.error('CSV File Failure')
    def writeCSVRow(self, fileName, filePath, fileSize, mTime, aTime, cTime, hashVal, own, grp, mod):
        self.writer.writerow( (fileName, filePath, fileSize, mTime, aTime, cTime, hashVal, own, grp, mod))
    def writerClose(self):
        self.csvFile.close()
                    
        
    