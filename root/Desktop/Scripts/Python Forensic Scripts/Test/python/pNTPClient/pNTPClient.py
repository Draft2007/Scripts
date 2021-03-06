import ntplib       # import the ntplib
import time         # import the Python time module

# url of the closest NIST certified NTP server
NIST = 'nist1-lv.ustiming.org'

# Create NTP client using the ntplib
ntp = ntplib.NTPClient()

# initiate an NTP client request for time
ntpResponse = ntp.request(NIST)

# Check that we received a response
if ntpResponse:
    now = time.time()
    diff = now - ntpResponse.tx_time
    print 'Difference:',
    print diff,
    print 'seconds'
    
    print 'Network Delay:',
    print ntpResponse.delay
    
    print 'UTC NIST : '+ time.strftime("%a. %d %b %Y %H: %M: %S + 0000",
    time.gmtime(int(ntpResponse.tx_time)))
    
    print 'UTC SYSTEM : '+ time.strftime("%a. %d %b %Y %H: %M: %S + 0000", time.gmtime(int(now)))
    
else:
    print 'No Response from Time Service'