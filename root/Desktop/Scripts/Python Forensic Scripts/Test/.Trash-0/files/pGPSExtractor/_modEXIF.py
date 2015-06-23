# Data Extraction - Python-Forensics
# Extract GPS Data from EXIF supported Images (jpg, tiff)
# Support Module
#
import os # Standard Library OS functions
from classLogging import _ForensicLog # Abstracted Forensic Logging Class
# import the Python Image Library
# along with TAGS and GPS related TAGS
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
#
# Extract EXIF Data
#
# Input: Full Pathname of the target image
#
# Return: gps Dictionary and selected EXIFData list
#
def ExtractGPSDictionary(fileName):
    try:
        pilImage = Image.open(fileName)
        EXIFData = pilImage._getEXIF()
    except Exception:
        # If exception occurs from PIL processing
        # Report the
        return None, None
    # Iterate through the EXIFData
    # Searching for GPS Tags
    imageTimeStamp = "NA"
    CameraModel = "NA"
    CameraMake = "NA"
    if EXIFData:
        for tag, theValue in EXIFData.items():
            # obtain the tag
            tagValue = TAGS.get(tag, tag)
            # Collect basic image data if available
            if tagValue =='DateTimeOriginal':
                imageTimeStamp = EXIFData.get(tag)
		print(imageTimeStamp)
            if tagValue == "Make":
                cameraMake = EXIFData.get(tag)
            if tagValue =='Model':
                cameraModel = EXIFData.get(tag)
            # check the tag for GPS
            if tagValue == "GPSInfo":
                # Found it !
                # Now create a Dictionary to hold the GPS Data
                gpsDictionary = {}
                # Loop through the GPS Information
                for curTag in theValue:
                    gpsTag = GPSTAGS.get(curTag, curTag)
                    gpsDictionary[gpsTag] = theValue[curTag]
                basicEXIFData = [imageTimeStamp, cameraMake, cameraModel]
                return gpsDictionary, basicEXIFData
    else:
        return None, None
# End ExtractGPSDictionary ===========================
#
# Extract the Latitude and Longitude Values
# From the gpsDictionary
#
def ExtractLatLon(gps):
    # to perform the calculation we need at least
    # lat, lon, latRef and lonRef
    if (GPSTAGS.has_key("GPSLatitude") and GPSTAGS.has_key("GPSLongitude") and GPSTAGS.has_key("GPSLatitudeRef") and GPSTAGS.has_key ("GPSLatitudeRef")):
        latitude = gps["GPSLatitude"]
        latitudeRef = gps["GPSLatitudeRef"]
        longitude = gps["GPSLongitude"]
        longitudeRef = gps["GPSLongitudeRef"]
        lat = ConvertToDegrees(latitude)
        lon = ConvertToDegrees(longitude)
        # Check Latitude Reference
        # If South of the Equator then lat value is negative
        if latitudeRef == "S":
            lat = 0 - lat
        # Check Longitude Reference
        # If West of the Prime Meridian in
        # Greenwich then the Longitude value is negative
        if longitudeRef == "W":
            lon = 0- lon
        gpsCoor = {"Lat": lat, "LatRef":latitudeRef, "Lon": lon, "LonRef": longitudeRef}
        return gpsCoor
    else:
        return None
# End Extract Lat Lon =================================
#
# Convert GPSCoordinates to Degrees
#
# Input gpsCoordinates value from in EXIF Format
#
def ConvertToDegrees(gpsCoordinate):
    d0 = gpsCoordinate[0][0]
    d1 = gpsCoordinate[0][1]
    try:
        degrees = float(d0) / float(d1)
    except:
        degrees = 0.0
    m0 = gpsCoordinate[1][0]
    m1 = gpsCoordinate[1][1]
    try:
        minutes = float(m0) / float(m1)
    except:
        minutes=0.0
    s0 = gpsCoordinate[2][0]
    s1 = gpsCoordinate[2][1]
    try:
        seconds = float(s0) / float(s1)
    except:
        seconds = 0.0
    floatCoordinate = float (degrees + (minutes / 60.0) + (seconds / 3600.0))
    return floatCoordinate