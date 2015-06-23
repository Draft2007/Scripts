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
import _pSearch

if __name__=='__main__':
    PSEARCH_VERSION = '1.0'
    # Turn on Logging
    logging.basicConfig(filename='pSearchLog.log',level=logging.DEBUG, format='%(asctime)s %(message)s')
    # Process the Command Line Arguments
    _pSearch.ParseCommandLine()
    log = logging.getLogger('main._pSearch')
    log.info("p-search started")
    # Record the Starting Time
    startTime = time.time()
	# Perform Keyword Search
    _pSearch.SearchWords()
    # Record the Ending Time
    endTime = time.time()
    duration = endTime - startTime
    logging.info('Elapsed Time:'+ str(duration) +'seconds')
    logging.info('')
    logging.info('Program Terminated Normally')
    