# pHashAndCollectMeta : Python File System Hash Program
# Author : B. Kaiser
# January 2015
# Version 1.0
#
import logging      				# Python Library logging functions
import time         				# Python Library time manipulation functions
import sys          				# Python Library system specific parameters
import _pHashAndCollectMeta       	# _pHashAndCollectMeta Support Function Module
import argparse     				# Python Library for parsing user supplied args

if __name__ == '__main__':
    PHASHANDCOLLECTMETA_VERSION = '1.0'
    # Turn on Logging
    logging.basicConfig(filename='pHashAndCollectMeta.log',level=logging.DEBUG,format='%(asctime)s %(message)s')
    # Process the Command Line Arguments
    _pHashAndCollectMeta.ParseCommandLine()
    # Record the Starting Time
    startTime = time.time()
    # Post the Start Scan Message to the Log
    logging.info('Welcome to pHashAndCollectMeta version 1... New Scan Started')
    _pHashAndCollectMeta.DisplayMessage('Welcome to pHashAndCollectMeta ... version 1')
    # Record some important information regarding the system
    logging.info('System:'+ sys.platform)
    logging.info('Version:'+ sys.version)
    # Traverse the file system directories and hash the files
    filesProcessed = _pHashAndCollectMeta.WalkPath()
    # Record the end time and calculate the duration
    endTime = time.time()
    duration = endTime - startTime
    logging.info('Files Processed:'+ str(filesProcessed) )
    logging.info('Elapsed Time:'+ str(duration) +'seconds')
    logging.info('Program Terminated Normally')
    _pfish.DisplayMessage("Program End")
    
    