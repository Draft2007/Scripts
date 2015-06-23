import csv #Python Standard Library - reader and writer for csv files
#
# Class: _CSVWriter
#
# Desc: Handles all methods related to comma separated value operations
#
# Methods constructor: Initializes the CSV File
# writeCVSRow: Writes a single row to the csv file
# writerClose: Closes the CSV File
class _CSVWriter:
    def __init__(self, fileName):
        try:
            # create a writer object and then write the header row
            self.csvFile = open(fileName,'wb')
            self.writer = csv.writer(self.csvFile, delimiter=',', quoting=csv.QUOTE_ALL)
            self.writer.writerow( ('Image Path','Make','Model','UTC Time', 'Lat Ref','Latitude','Lon Ref','Longitude','Alt Ref','Altitude') )
        except:
            log.error('CSV File Failure')
    def writeCSVRow(self, fileName, cameraMake, cameraModel, utc, latRef, latValue, lonRef, lonValue, altRef, altValue):
        latStr ='%.8f'% latValue
        lonStr='%.8f'% lonValue
        altStr ='%.8f'% altValue
        self.writer.writerow(fileName, cameraMake, cameraModel, utc, latRef, latStr, lonRef, lonStr, altRef, AltStr)
    def __del__(self):
        self.csvFile.close()