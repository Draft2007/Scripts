from django import template
register = template.Library()
from django.template.defaultfilters import stringfilter
#from django.utils import simplejson
from django.core.serializers import serialize
from django.db.models.query import QuerySet
from webapp.settings import CUCKOO_FOUND, CUCKOO_PATH
from django.db.models.fields import FieldDoesNotExist
import binascii
import base64
import json 
#from home.usb_classes import uclasses
from home.usb_vid_pid import vid_pid
from home.usb_vid  import vid
from home.usb_data import classes
import datetime

@register.filter
def get_last_seen(station):
    last_seen = datetime.datetime.now() - station.last_seen
    datetime.timedelta(0, 125, 749430)
    last_seen_minutes = divmod(last_seen.total_seconds(), 60)[0]
    return int(last_seen_minutes)

@register.assignment_tag
def get_vendor_product_names(vendor_id,product_id):
    vendor_name = vendor_id
    product_name = product_id
    
    if vendor_id.lower() in vid:
        vendor_name = vid[vendor_id.lower()]
    
        if product_id.lower() in vid_pid[vendor_id.lower()]:
            product_name = vid_pid[vendor_id.lower()][product_id.lower()]
        
    return vendor_name, product_name

@register.assignment_tag
def get_device_type(device):
    hid = False
    for data in device.usb_class.split('|'):
        if not data:
            return 'USB'
        print data
        cls,subcls,proto = data.split('/')
        cls = int(cls)
        subcls = int(subcls)
        proto = int(proto)

        if cls == 3:
            hid = True
            if subcls in [0,1]:
                if proto == 1 or 'keyboard' in device.caption.lower():
                    return 'Keyboard'
                elif proto == 2 or 'mouse' in device.caption.lower():
                    return 'Mouse'
                
        elif cls == 6 and subcls == 1 and proto == 1:
            print 'Here'
            return 'Phone' 
        
    if hid:
        return 'HID'
    else:
        return 'USB'
            
@register.assignment_tag
def get_usb_data(data):
    print "data:" + data
    if not data:
        return
    cls,subcls,prot = data.split('/')
    cls = int(cls)
    subcls = int(subcls)
    prot = int(prot)
    if cls in classes:
        class_name = '%s (0x%x)' % (classes[cls]['name'], cls)
        subclasses = classes[cls]['subclasses']
        
        if subcls in subclasses:
            subclass_name = '%s (0x%x)' % (subclasses[subcls]['name'], subcls)
            protocols = subclasses[subcls]['protocols']
            if prot in protocols:
                protocol_name = '%s (0x%x)' % (protocols[prot],prot)
            else:
                protocol_name = '%x' % prot
        else:
            subclass_name = '%x' % subcls
            protocol_name = '%x' % prot
    else:
        class_name = '%x' % cls
        subclass_name = '%x' % subcls
        protocol_name = '%x' % prot
        
    return class_name,subclass_name,protocol_name

@register.filter
def split(str,char):
    return str.split(char)

@register.filter
@stringfilter
def debug_view(str):
    b=""
    try:
        d = binascii.a2b_hex(str)
        for letter in d:
            if letter.isalnum():
                b+=letter
            else:
                b+="."
    except:
        pass

    i=0
    f=0
    buf=""
    for c in range(0,512):
        i = i +16
        f = f +8
        buf+=str[i:16+i]
        buf+="    "
        buf+=b[f:8+f]
        buf+="\n"
    return buf
        


@register.filter
@stringfilter
def a2b_hex(str):
    buf=""
    try:
        d = binascii.a2b_hex(str)
        for letter in d:
            if letter.isalnum():
                buf+=letter
            else:
                buf+="."
    except:
        pass
            
    
    return buf



@register.filter
@stringfilter
def b2a_hex(str):
    return binascii.b2a_hex(str)
    

@register.filter
@stringfilter
def escape_backslash(str):
    return str.replace('\\','\\\\')

@register.filter
@stringfilter
def get_name(str):
    return str.split('.')[0]

@register.filter
@stringfilter
def b64encode(str):
    return base64.b64encode(str)


@register.filter
@stringfilter
def b64decode(str):
    return base64.b64decode(str)

@register.assignment_tag
def get_pagination_range( total, value ):
    """
    Get a n pages pagination range.
    """
    n = 10
    if value <= n:
        maxium = min(total, n * 2 + 1)
        print maxium
        return xrange(1, maxium + 1)
    
    elif total - value <= n:
        print total
        print total - (n * 2 + 1)
        return xrange(total - (n * 2 + 1), total )
    else:
        return xrange(max(value - n, 1), min(total,value + n) )

@register.filter
def jsonify(object):
    if isinstance(object, QuerySet):
        return serialize('json', object)
    #return simplejson.dumps(object)
    return json.dumps(object)

@register.filter
def get_tags(binary):
    converted_tags = []
    tags = binary.tag.names()
    return ','.join(tags)


@register.assignment_tag
def get_cuckoo_status(): 
    if CUCKOO_FOUND:
        return True
    else:
        return False
        
@register.assignment_tag()
def get_search_info(request, sessid):
    data = request.session.get(sessid,'')
    if data:
        return data[3]
    else:
        return ''
