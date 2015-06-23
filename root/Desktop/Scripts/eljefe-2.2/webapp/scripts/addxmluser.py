import sys
import os
import getpass



if "." not in sys.path: sys.path.append(".")
if "../" not in sys.path: sys.path.append("../")
if "../../" not in sys.path: sys.path.append("../../")
os.environ["DJANGO_SETTINGS_MODULE"] = "webapp.settings"

from home.models import *




if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "Usage: %s USERNAME" % sys.argv[0]
        sys.exit(0)
    else:
        usern = sys.argv[1]
        passw = getpass.getpass()
        xmlu = xmlusers()
        xmlu.username= usern
        xmlu.password = passw
        xmlu.save()
        print "Username added"


            
