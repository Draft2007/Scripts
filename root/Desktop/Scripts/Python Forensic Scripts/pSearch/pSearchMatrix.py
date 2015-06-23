#
# p-search: Python Word Search
# Author: Brian Kaiser
# January 2015
# Version 1.0
#
# Simple p-search Python program
#
import logging
import time
import _pSearchMatrix

if __name__=='__main__':
    PSEARCHMatrix_VERSION = '1.0'
    # Turn on Logging
    logging.basicConfig(filename='pSearchLogMatrix.log',level=logging.DEBUG, format='%(asctime)s %(message)s')
    # Process the Command Line Arguments
    _pSearchMatrix.ParseCommandLine()
    log = logging.getLogger('main._psearch')
    startTime = time.time()
    log.info("p-searchMatrix started")
    # Record the Starting Time
    # Perform Keyword Search
    _pSearchMatrix.SearchWords()
    # Record the Ending Time
    endTime = time.time()
    duration = endTime - startTime
    logging.info('Elapsed Time:'+ str(duration) +'seconds')
    logging.info('')
    logging.info('Program Terminated Normally')
    