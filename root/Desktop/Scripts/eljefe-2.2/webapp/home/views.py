from django.db.models import Q
from django.conf import settings
from django.contrib.admin.models import LogEntry
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required, user_passes_test, permission_required
from django.contrib.auth.models import User
from django.contrib.contenttypes.models import ContentType
from django.core.cache import cache
from django.core.paginator import Paginator, InvalidPage, EmptyPage
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseServerError, Http404, HttpResponseBadRequest
from django.shortcuts import render_to_response, get_object_or_404
from django.template import Context, loader, RequestContext
from django.template.defaultfilters import slugify
from django.db.models import Min
from django.utils.encoding import force_unicode
from django.core.context_processors import csrf
from django.views.decorators.csrf import csrf_protect
from datetime import timedelta
from django.utils import timezone
from webapp.settings import HOMEDIR, PROJECT_ROOT, CAMAL_APIKEY, CUCKOO_FOUND
import hashlib
from django.shortcuts import get_object_or_404
import json
from forms import *
from models import *
import datetime
import base64
import pymongo
import ntpath
import xmlrpclib
from HTMLParser import HTMLParser
import urllib2
from django.core.urlresolvers import reverse
import requests
from itertools import chain
import numpy
from ssl_utils import *
import os
import itertools 
from home.templatetags.version import get_version
from usb_vid import vid
from usb_vid_pid import vid_pid
from usb_data import classes

if CUCKOO_FOUND:
    from lib.cuckoo.core.database import Database, TASK_PENDING
    from lib.cuckoo.common.constants import CUCKOO_ROOT
    from lib.cuckoo.common.config import Config
    from lib.cuckoo.common.objects import Dictionary
    
    results_db = pymongo.connection.Connection(settings.MONGO_HOST, 
                                               settings.MONGO_PORT).cuckoo

tags = {'1': 'Reviewed',
        '2': 'Malware',
        '3': 'Inspect Later'
        }


event_types = {}
event_types["Handle Count"] = 'handle_count'
event_types["Virtual Size"] = 'virtual_size'
event_types["Thread Count"] = 'thread_count'
event_types["Peak Virtual Size"] = 'peak_virtual_size'
event_types["Quota Paged Pool Usage"] = 'quota_paged_pool_usage'
event_types["Quota Non Paged Pool Usage"] = 'quota_non_paged_pool_usage'
event_types["Quota Peak Paged Pool Usage"] = 'quota_peak_paged_pool_usage'
event_types["Quota Peak Non Paged Pool Usage"] = 'quota_peak_non_paged_pool_usage'
event_types["Write Operation Count"] = 'write_operation_count'
event_types["User Mode Time"] = 'user_mode_time'


class MyHTMLParser(HTMLParser):
    MalwareMSG = "ltr text-red"
    found = False
    def handle_starttag(self, tag, attrs):
        if tag == "td":
            for at, data in attrs:
                if at =="class":
                    if data == self.MalwareMSG:
                        self.found = True
                        return
                    
def _parse_query(query):
    return [(a[4:].strip(), False) if a.startswith('not ') else (a.strip(), True)\
            for a in query.split(' and ')]

def _get_query(request):
    q = request.POST.get('q', '')
    if q:
        params = re.split(r'(\w+):', q)
        data = {}

        first_param = params.pop(0)
        if first_param:
            data['software'] = _parse_query(first_param.strip())

        if len(params) % 2 != 0:
            return {}

        while params:
            criteria = params.pop(0)
            value = params.pop(0)
            data[criteria] = _parse_query(value.strip())

    else:
        criterias = request.POST.getlist('criteria')
        operators = request.POST.getlist('operator')
        values = request.POST.getlist('value')

        # group query data
        data = {}
        for criteria, op, value in zip(criterias, operators, values):
            d = data.get(criteria, [])
            d.append((value, op != 'not'))
            data[criteria] = d

    return data

def _get_query_string(query):
    # build query
    res = []
    for criteria, params in query.iteritems():
        op_params = map(lambda x: x[0] if x[1] else 'not %s' % x[0], params)
        str_query = '%s: %s' % (criteria, ' and '.join(op_params))
        res.append(str_query)
    q = ' '.join(res)
    return q

def _get_search_results(request, query):
    configurations = _get_configurations(request)
    bugs = Bug.objects.filter(configuration__in=configurations)

    softwares = query.pop('software', None)
    if softwares is not None:
        desired = [soft[0] for soft in softwares if soft[1]]
        bugs = bugs.filter(configuration__ownerversion__software__name__in=desired)

    for criteria, restrictions in query.iteritems():
        criteria_filter = SEARCH_CRITERIAS.get(criteria, None)

        if criteria_filter is None:
            continue

        for value, include in restrictions:
            bug_filter = {criteria_filter: value}
            if include:
                bugs = bugs.filter(**bug_filter)
            else:
                bugs = bugs.exclude(**bug_filter)
    return bugs

_criteria_types = [(u"SHA1",u"SHA1 Hash"),
                   (u"binary",u"Binary"),
                   (u"station",u"Station"),
                   ]

def _chew_query(query):
    result = []
    for name,crit_confs in query.items():
        for crit in crit_confs:
            result.append(
                {'crit_id':name,
                 'operator':crit[1],
                 'value':crit[0]}
            )
    return result


@login_required
@csrf_protect
def dropall(request):
    """
    Drop everything!
    """
    # all foreign objects are deleted aswell
    station_list = stations.objects.all().delete()

    return render_to_response('home/index.html',
                              {
                                  }, context_instance=RequestContext(request))




def createSessionId(string):
    n = datetime.datetime.now()
    sessid=hashlib.sha1(string+"%s" % n)
    return sessid.hexdigest()


@login_required
@csrf_protect
def requestContent(request,sessid=0,page=1):
    if not request.session.has_key(sessid):
        print "Do not have key sessionid in our session for request content: %s"%sessid
        return render_to_response('home/tablecontent.html', 
                                  {
                                  } )

    table_type,object_type,display,cleaned= request.session[sessid]
    print table_type
    print object_type

    if table_type == "childevent":
        event_req = events.objects.get(id=cleaned)
        objects = events.objects.filter(parent_binary__binary_sha1=event_req.binary.binary_sha1,parent_binary__pid=event_req.binary.pid)
    if table_type == "intrusion":
	#print 'intrusion'
        startdate = None
        enddate = None
        dodate = False
        if cleaned.has_key("startdate") and cleaned.has_key("enddate"):
            startdate = cleaned["startdate"]
            enddate = cleaned["enddate"]
        if startdate and not enddate:
            enddate = "2100-01-01 00:00:00"
            dodate = True
        if enddate and not startdate:
            startdate = "2000-01-01 00:00:00"
            dodate = True
        if startdate and enddate:
            dodate = True

        if cleaned.has_key("method") and cleaned["method"] == "ENTROPY: SUSPICIOUS":
            object_type = "binary"
            display = ["Station","Path","Binary SHA1"]
            if dodate:
                firstpass = events.objects.filter(event_timestamp__lte = enddate).filter(event_timestamp__gte = startdate)
                objects=[]
                for ev in firstpass:
                    if ev.binary.entropy < 3:
                        objects.append(ev.binary)
            else:
                objects = binaries.objects.filter(entropy__lt=3)


        if cleaned.has_key("method") and cleaned["method"] == "PRIVILEGES: NON-SYSTEM to SYSTEM":
            object_type = "event"
            display = ["Date","Parent Binary","Binary","Cmdline","Username","Station"]
            if dodate:
                firstpass = events.objects.filter(event_timestamp__lte = enddate).filter(event_timestamp__gte = startdate).filter(username__icontains="system")
                d={}

                objects=[]
                for ev in firstpass:
                    secondpass = events.objects.filter(binary__binary_sha1__icontains=ev.parent_binary.binary_sha1).filter(binary__pid__iexact=ev.parent_binary.pid).exclude(username__icontains="system")
                    for ev2 in secondpass:
                        d[ev.id]=ev

                for key in d:
                    objects.append(d[key])

            else:
                firstpass = events.objects.filter(username__icontains="system")
                d={}

                objects=[]
                for ev in firstpass:
                    parents = events.objects.filter(binary__binary_sha1__icontains=ev.parent_binary.binary_sha1,binary__pid__iexact=ev.parent_binary.pid, event_timestamp__lt = ev.event_timestamp).exclude(username__icontains="system").order_by('-event_timestamp')
		    if parents and 'SYSTEM' not in parents[0].username:
			objects.append(ev)


        if cleaned.has_key("method") and cleaned["method"] == "FLAGS: SUSPICIOUS":
            object_type = "event"
            display = ["Date","Parent Binary","Binary","Cmdline","Username","Station"]
            if dodate:
                objects = events.objects.filter(event_timestamp__lte = enddate).filter(event_timestamp__gte = startdate).filter(binary__file_path__icontains="iexplore").filter(flags__icontains="CREATE_SUSPENDED DETACHED_PROCESS")
            else:
                objects = events.objects.filter(binary__file_path__icontains="iexplore").filter(flags__icontains="CREATE_SUSPENDED DETACHED_PROCESS")




        if cleaned.has_key("method") and cleaned["method"] == "EXECUTING PARENT: LSASS.exe":
            object_type = "event"
            display = ["Date","Parent Binary","Binary","Cmdline","Username","Station"]
            if dodate:
                objects = events.objects.filter(event_timestamp__lte = enddate).filter(event_timestamp__gte = startdate).filter(parent_binary__file_path__icontains="java")

            else:

                objects = events.objects.filter(parent_binary__file_path__icontains="lsass.exe")


        if cleaned.has_key("method") and cleaned["method"] == "CALL CHAIN: iexplorer->java->cmd":
            object_type = "event"
            display = ["Date","Parent Binary","Binary","Cmdline","Username","Station"]
            if dodate:
                objects = events.objects.filter(event_timestamp__lte = enddate).filter(event_timestamp__gte = startdate).filter(parent_binary__file_path__icontains="java").filter(binary__file_path__icontains="cmd")
            else:
                objects = events.objects.filter(parent_binary__file_path__icontains="java").filter(binary__file_path__icontains="cmd")



    if table_type == "vieweventsevents":
        objects = events.objects.filter(parent_binary=cleaned).order_by('-event_timestamp')

    if table_type == "viewbinariesevents":
        objects = binaries.objects.filter(station=cleaned).order_by('last_execution')

    if table_type == "viewevents":
	process_events = events.objects.filter(station=cleaned)		    
	usb_objects = usb_events.objects.filter(station=cleaned)
	mass_objects = usb_mass_storage_events.objects.filter(station=cleaned)
	all_objects = list(chain(process_events,
	                         usb_objects, 
	                         mass_objects)) 
	
	objects = sorted(all_objects,
	                 reverse=True,
	                 key=lambda instance: instance.event_timestamp)		
	    
    if table_type == "viewbinaries":
        objects = binaries.objects.filter(station=cleaned).order_by('last_execution')
	
    if table_type == "vieweventsbybinary":
        objects = events.objects.all().filter(binary=cleaned).order_by('-event_timestamp')
        if not objects:
            # if objects is None is maybe because it's a parent binary 
            objects = events.objects.all().filter(parent_binary=cleaned).order_by('-event_timestamp')

    if table_type == "viewprocesses":
        #obj_bin = binaries.objects.filter(station=cleaned).distinct('file_path')
        #objects = running_processes.objects.all().filter(station=cleaned)
        #objects = objects.filter(binary__in=obj_bin).order_by('-event_timestamp')
        #objects = objects.distinct('proc_bin')
        #objects = running_processes.objects.all().filter(station=cleaned).order_by('-event_timestamp')
        #objects = unique_processes.objects.all()
        objects = running_processes.objects.all().filter(station=cleaned).order_by('-creation_date')


    if table_type == "content":
        if object_type == "station":
            objects = stations.objects.all()
        if object_type == "event":
            #objects = events.objects.all().order_by('-event_timestamp')
            event_objects = events.objects.all().order_by('-event_timestamp')
            usb_objects = usb_events.objects.all().order_by('-event_timestamp')
            usb_ms_objects = usb_mass_storage_events.objects.all().order_by('-event_timestamp')
            all_objects = list(chain(event_objects, usb_ms_objects, usb_objects))           
            
            #print "eventos " + str(len(event_objects))
            #print "usb eventos " + str(len(usb_objects))
            #print "usb ms eventos " + str(len(usb_ms_objects))
            #print "Total " + str(len(all_objects))
            objects = sorted( all_objects,reverse=True,key=lambda instance: instance.event_timestamp)
            #print "Total " + str(len(result_list))

        if object_type == "binary":
            objects = binaries.objects.all().order_by('last_execution')
        if object_type == "unique":
            # Retrieve all binaries that only have one related event
            objects = unique_executions.objects.all()


    if table_type == "search":
        if object_type == "station":
            ip = cleaned['IP']
            hostname = cleaned['hostname']
            objects = stations.objects.filter(ip_address__icontains=ip,hostname__icontains=hostname)
        if object_type == "event":
	    field = cleaned['field']
	    operator = cleaned['operator']
	    value = cleaned['value']
	    
	    numeric_symbols = {"<":'lt',">":'gt',
		               '==':'exact','!=':'neq',
		               '<=':'lte','>=':'gte'
		               }
	    
	    if field == 'station':
		args = {'{0}__{1}'.format('station__hostname','icontains') : value}	
		process_events = events.objects.filter(**args)		    
		usb_objects = usb_events.objects.filter(**args)
		mass_objects = usb_mass_storage_events.objects.filter(**args)
		all_objects = list(chain(process_events,
	                                 usb_objects, 
	                                 mass_objects)) 
		
		objects = sorted(all_objects,
		                 reverse=True,
		                 key=lambda instance: instance.event_timestamp)	  		
		
	    elif field == 'event_timestamp':
		try:
		    time_value = datetime.datetime.strptime(value, "%m/%d/%Y %H:%M:%S")  	
		
		    if operator == '!=':
			args = {'{0}__{1}'.format(field, 'exact') : time_value}
			process_events = events.objects.exclude(**args)
			usb_objects = usb_events.objects.exclude(**args)
			mass_objects = usb_mass_storage_events.objects.exclude(**args)
			all_objects = list(chain(process_events,
			                         usb_objects, 
			                         mass_objects)) 
		    else:
			op = numeric_symbols[operator]
			args = {'{0}__{1}'.format(field, op) : time_value}
			
			process_events = events.objects.filter(**args)		    
			usb_objects = usb_events.objects.filter(**args)
			mass_objects = usb_mass_storage_events.objects.filter(**args)
			all_objects = list(chain(process_events,
			                         usb_objects, 
			                         mass_objects)) 
		except: 
		    process_events = events.objects.all()
		    usb_objects = usb_events.objects.all()
		    mass_objects = usb_mass_storage_events.objects.all()
		    all_objects = list(chain(process_events,
		                             usb_objects, 
		                             mass_objects)) 		    
		objects = sorted(all_objects,
                                 reverse=True,
                                 key=lambda instance: instance.event_timestamp)	    
	    else:
		if not cleaned:
		    objects = events.objects.all()
		
		if operator not in numeric_symbols:
		    if field in ['binary', 'parent_binary']:
			args = {'{0}__{1}'.format('binary__file_path','icontains') : value}
		    else:
			args = {'{0}__{1}'.format(field,'icontains') : value}
		    objects = events.objects.filter(**args)	
		else:		
		    op = numeric_symbols[operator]
		    if operator == '!=':
			args = {'{0}__{1}'.format(field, 'exact') : float(value)}
			objects = events.objects.exclude(**args)	
		    else:
			args = {'{0}__{1}'.format(field, op) : float(value)}
			objects = events.objects.filter(**args)
		
        if object_type == "binary":
            file_path = cleaned['binary_name']
            binary_md5 = cleaned['binary_md5']
            binary_sha1 = cleaned['binary_sha1']
            binary_sha256 = cleaned['binary_sha256']
            code_section_sha1 = cleaned['code_sha1']

            objects = binaries.objects.filter(file_path__icontains=file_path,\
                                              binary_md5__icontains=binary_md5,\
                                              binary_sha1__icontains=binary_sha1,\
                                              binary_sha256__icontains=binary_sha256,\
                                              code_section_sha1__icontains=code_section_sha1)


    paginator = Paginator(objects, 25 ) # Show 25 contacts per page
    try:
        objlist = paginator.page(page)
    except (EmptyPage, InvalidPage):
        objlist = paginator.page(paginator.num_pages)

    content = []
    if object_type == "station":
	content = objlist
	return render_to_response('home/stationscontent.html', 
	                          locals(),
	                          context_instance=RequestContext(request))           

    if object_type == "event" or object_type == "event_binary_filter":
	content = objlist
	return render_to_response('home/eventscontent.html', 
	                          locals(),
	                          context_instance=RequestContext(request))  

            
    if object_type == "process":
        for entry in objlist.object_list:
            #show = (entry.binary.file_path, entry.process.pid, entry.process.cmdline, entry.process.username)
            show = (entry.binary.file_path, entry.pid, entry.cmdline, entry.username)
            content.append((" ",(entry.binary.id,0),show))

    if object_type == "binary":
	content = objlist.object_list
	return render_to_response('home/binariescontent.html', 
	                          locals(),
	                          context_instance=RequestContext(request))	

    if object_type == "unique":
	content = objlist.object_list
	return render_to_response('home/unique_binariescontent.html', 
	                          locals(),
	                          context_instance=RequestContext(request))
    if table_type == "childevent":

        content=[]
        for entry in objlist.object_list:
            show = (entry.station.hostname, entry.binary.file_path, entry.flags, entry.username,entry.event_timestamp,entry.cmdline)
            content.append((" ",(entry.station.id,entry.binary.id,entry.id,entry.parent_binary.id),show))   





    return render_to_response('home/tablecontent.html', 
                              {
                                  'objlist': objlist,
                                  'display': display,
                                  'content': content,
                                  'object_type':object_type,
                                  'sessid':sessid,
                              } )


@login_required
@csrf_protect
def requestUSBContent(request,sessid=0,page=1):
    if not request.session.has_key(sessid):
        print "Do not have key sessionid in our session for request content: %s"%sessid
        return render_to_response('home/tablecontent.html', 
                                  {
                                  } )

    table_type,object_type,display,cleaned= request.session[sessid]

    if table_type == "content":
        if object_type == "station":
            objects = stations.objects.all()
        if object_type == "event":
            usb_objects = usb_events.objects.all().order_by('-event_timestamp')
            usb_ms_objects = usb_mass_storage_events.objects.all().order_by('-event_timestamp')
            all_objects = list(chain(usb_ms_objects, usb_objects))           
            
            objects = sorted( all_objects,reverse=True,key=lambda instance: instance.event_timestamp)
	    
    typ = None
    
    if table_type == "search":
        if object_type == "event":
	    typ = cleaned['type']
	    field = cleaned['field']
	    operator = cleaned['operator']
	    value = cleaned['value']
	    
	    numeric_symbols = {"<":'lt',">":'gt',
		               '==':'exact','!=':'neq',
		               '<=':'lte','>=':'gte'
		               }
	    
	    valid_fields = [fld.name for fld in usb_mass_storage_events._meta.fields]
	    valid_fields += [fld.name for fld in usb_events._meta.fields]
	    
	    for fld in usb_mass_storage._meta.fields:
		valid_fields.append('mass_storage_device__%s' % fld.name)
		
	    for fld in usb_devices._meta.fields:
		valid_fields.append('device__%s' % fld.name)
		
	    if field not in valid_fields:
		raise Http404
	    
	    if field == 'event_timestamp':
		try:
		    time_value = datetime.datetime.strptime(value, "%m/%d/%Y %H:%M:%S")		    
		
		    if operator == '!=':
			args = {'{0}__{1}'.format(field, 'exact') : time_value}
			
			usb_objects = usb_events.objects.exclude(**args)
			mass_objects = usb_mass_storage_events.objects.exclude(**args)
			all_objects = list(chain(usb_objects, mass_objects)) 
		    else:
			op = numeric_symbols[operator]
			args = {'{0}__{1}'.format(field, op) : time_value}
			
			usb_objects = usb_events.objects.filter(**args)
			mass_objects = usb_mass_storage_events.objects.filter(**args)
			all_objects = list(chain(usb_objects, mass_objects))
			
		except:
		    usb_objects = usb_events.objects.all()
		    mass_objects = usb_mass_storage_events.objects.all()
		    all_objects = list(chain(usb_objects, mass_objects))
		    
		objects = sorted(all_objects,
		                 reverse=True,
                                 key=lambda instance: instance.event_timestamp)
	    else:
		if typ == "usb":
		    if not cleaned:
			usb_objects = usb_events.objects.all()
			
		    if field == 'station':
			args = {'{0}__{1}'.format('station__hostname','icontains') : value}
			usb_objects = usb_events.objects.filter(**args)
			
		    else:
			if operator not in numeric_symbols:
			    args = {'{0}__{1}'.format(field,'icontains') : value}
			    usb_objects = usb_events.objects.filter(**args)
			else:
			    op = numeric_symbols[operator]
			    if operator == '!=':
				args = {'{0}__{1}'.format(field, 'exact') : float(value)}
				usb_objects = usb_events.objects.exclude(**args)
			    else:
				args = {'{0}__{1}'.format(field, op) : float(value)}
				usb_objects = usb_events.objects.filter(**args)
				
		    objects = sorted(usb_objects,
		                     reverse=True,
		                     key=lambda e: e.event_timestamp)
	
		else:
		    if not cleaned:
			mass_objects = usb_mass_storage_events.objects.all()
			args = {'{0}__{1}'.format('station__hostname','icontains') : value}

		    if field == 'station':
			args = {'{0}__{1}'.format('station__hostname','icontains') : value} 
			mass_objects = usb_mass_storage_events.objects.filter(**args)
			
		    else:
			if operator not in numeric_symbols:
			    args = {'{0}__{1}'.format(field,'icontains') : value}
			    mass_objects = usb_mass_storage_events.objects.filter(**args)	
			    		    
			else:
			    op = numeric_symbols[operator]
			    if operator == '!=':
				args = {'{0}__{1}'.format(field, 'exact') : float(value)}
				mass_objects = usb_mass_storage_events.objects.exclude(**args)	
			    else:
				args = {'{0}__{1}'.format(field, op) : float(value)}
				mass_objects = usb_mass_storage_events.objects.filter(**args)
    
		    objects = sorted(mass_objects,
		                     reverse=True,
		                     key=lambda e: e.event_timestamp)		
		    
    paginator = Paginator(objects, 25 ) # Show 25 contacts per page
    try:
        objlist = paginator.page(page)
    except (EmptyPage, InvalidPage):
        objlist = paginator.page(paginator.num_pages)

    
    content = []
    if object_type == "event":
	if not typ or field == 'event_timestamp':
	    content = objlist
	    multiple_usb_events = True
	    return render_to_response('home/allusbcontent.html', 
		                      locals(),
		                      context_instance=RequestContext(request))  
	elif typ == 'usb':
	    content = objlist
	    return render_to_response('home/usbcontent.html', 
			                  locals(),
			                  context_instance=RequestContext(request))	
	elif typ == 'mass_storage':
	    content = objlist
	    return render_to_response('home/mscontent.html', 
	                              locals(),
	                              context_instance=RequestContext(request))	    
	
	#if type(entry) is usb_mass_storage_events:
	#    #print "is usb_event"
	#    show = (entry.station.hostname, entry.mass_storage_device.caption,entry.status,entry.logical_drive,entry.event_timestamp,entry.mass_storage_device.serial_number, "USB_MS","USB" )
	#    content.append((" ",(entry.station.id,entry.mass_storage_device.id,entry.id),show))   

    


@login_required
@csrf_protect
def firstpage(request,editing_search=False):  
    context = {'criteria_types':_criteria_types}
    if request.method == "POST":
        #reportform = CreateReportForm()
        query = _get_query(request)
        request.session['last_logic_search'] = _chew_query(query)
        bugs = _get_search_results(request, query)
        return render_to_response('home/logic_results.html',
                                  {'bugs': bugs,
                                   #                          'reportform': reportform,
                                   'query': _get_query_string(query)},
                                  context_instance=RequestContext(request))
    elif request.method == "GET":
        if editing_search:
            context['prev_search'] = request.session.get('last_logic_search',{})


    return render_to_response('home/index.html',
                              context,
                              context_instance=RequestContext(request))

@csrf_protect    
@login_required    
def events_page(request):
    """
    List events
    """
    events_list = None
    if request.method == 'POST':
        searchform = eventsSearch(request.POST)
        if searchform.is_valid():
            cleaned = searchform.cleaned_data
            sessid = createSessionId(request.session._session_key)
            table_type = "search"
            object_type = "event"
            display = ["Date","Parent Binary","Binary","Cmdline","Username","Station"]
            request.session[sessid]=[table_type,object_type,display,cleaned]
    else:
	sessid = createSessionId(request.session._session_key)
	
	table_type = "content"
	object_type = "event"
	display = ["Date","Parent Binary","Binary","Cmdline","Username","Station"]
	cleaned = {}
	
	request.session[sessid]=[table_type,object_type,display,cleaned]        
	searchform = eventsSearch()


    return render_to_response('home/events.html',
                              {'sessid': sessid  ,
                               'searchform':searchform,
                               }, context_instance=RequestContext(request))    


@csrf_protect    
@login_required    
def binary_filter(request, binary_id):
    """
    List events
    """
    
    binary = binaries.objects.get(id = binary_id)
    binary_name = ntpath.basename(binary.file_path)
    cleaned = {'username': '', 'binary': binary_name, 'parent': binary_name}
    sessid = createSessionId(request.session._session_key)
    table_type = "search"
    object_type = "event_binary_filter"
    display = ["Date","Parent Binary","Binary","Cmdline","Username","Station"]
    request.session[sessid]=[table_type,object_type,display,cleaned]

    return render_to_response('home/events.html',
                              locals(),
                              context_instance=RequestContext(request))    

@csrf_protect
@login_required
def binaries_page(request,page_number,tag_filter):
    """
    List binaries
    """
    #print tag_filter
    sessid = createSessionId(request.session._session_key)
    if tag_filter == 'All':
        #objects = binaries.objects.all().order_by('last_execution')
        objects = binaries.objects.all().order_by('pid')
    else:
        objects = binaries.objects.filter(tag__name__in=tag_filter.split(',')).order_by('last_execution')

    paginator = Paginator(objects, 25 ) # Show 25 contacts per page
    try:
        objlist = paginator.page(page_number)
    except (EmptyPage, InvalidPage):
        objlist = paginator.page(paginator.num_pages)


    table_type = "content"
    object_type = "binary"
    display = ["Station","Path","Binary SHA1"]
    cleaned = {}

    request.session[sessid]=[table_type,object_type,display,cleaned]

    str_tags = tags.values()

    return render_to_response('home/binaries.html', 
                              locals(),
                              context_instance=RequestContext(request))


@csrf_protect        
@login_required
def stations_page(request):
    """
    List stations
    """

    sessid = createSessionId(request.session._session_key)

    table_type = "content"
    object_type = "station"
    display = ["Last Seen","Hostname","IP Address"]
    cleaned = {}

    request.session[sessid]=[table_type,object_type,display,cleaned]

    return render_to_response('home/stations.html',
                              {
                                  'sessid' : sessid,
                                  }, context_instance=RequestContext(request))




@csrf_protect        
@login_required
def usb_search(request):
    """
    List usb events 
    """
    sessid = createSessionId(request.session._session_key)
    
    fields = {}
    model = usb_mass_storage_events  
    inputs = []
    for field in model._meta.fields:
	if field.name not in ['id','mass_storage_device']:
	    input_dict = {}
	    input_dict['name'] = field.name
	    input_dict['type'] = field.get_internal_type()
	    inputs.append(input_dict)
	        
    model = usb_mass_storage	
    for field in model._meta.fields:
	if field.name not in ['id']:
	    input_dict = {}
	    input_dict['name'] = 'mass_storage_device__%s' % field.name
	    input_dict['type'] = field.get_internal_type()
	    inputs.append(input_dict)
	    
    fields['mass_storage'] = inputs
    
    inputs = []
    model = usb_events
    for field in model._meta.fields:
	if field.name not in ['id','device']:
	    input_dict = {}
	    input_dict['name'] = field.name
	    input_dict['type'] = field.get_internal_type()
	    inputs.append(input_dict)
	    
    
    model = usb_devices
    for field in model._meta.fields:
	if field.name not in ['id']:
	    input_dict = {}
	    input_dict['name'] = 'device__%s' % field.name
	    input_dict['type'] = field.get_internal_type()
	    inputs.append(input_dict)
	    
    fields['usb'] = inputs
    
    inputs = ['USB','Mass Storage']
    
    numeric_symbols = {op:op for op in ["<",">",'==','!=','<=','>=']}    
    if request.method == 'POST':
	display = ["Date","Parent Binary","Binary","Cmdline","Username","Station"]
	
        typ = request.POST.get('type','')
        field = request.POST.get('field','')
	operator = request.POST.get('operator','')
	value = request.POST.get(field,'')
	
	cleaned = {}
	cleaned['type'] = typ	
	cleaned['field'] = field
	cleaned['operator'] = operator
	cleaned['value'] = value
	
	table_type = "search"
	object_type = "event"
    else:
	display = ["Date","Info","","","",""]
	
	table_type = "content"
	object_type = "event"
	cleaned = {}	
	
    request.session[sessid]=[table_type,object_type,display,cleaned]

    return render_to_response('home/usbsearch.html',
                              locals(),
                              context_instance=RequestContext(request))

@csrf_protect        
@login_required
def eventssearch(request):
    """
    List events 
    """
    sessid = createSessionId(request.session._session_key)
    display = ["Date","Parent Binary","Binary","Cmdline","Username","Station"]
    
    model = events
    inputs = []
    for field in model._meta.fields:
	if field.name not in ['id']:
	    input_dict = {}
	    input_dict['name'] = field.name
	    input_dict['type'] = field.get_internal_type()
	    inputs.append(input_dict)

    numeric_symbols = {op:op for op in ["<",">",'==','!=','<=','>=']}    
    if request.method == 'POST':
        field = request.POST.get('field','')
	operator = request.POST.get('operator','')
	value = request.POST.get(field,'')
	
	cleaned = {}
	cleaned['field'] = field
	cleaned['operator'] = operator
	cleaned['value'] = value
	
	table_type = "search"
	object_type = "event"
    else:
	table_type = "content"
	object_type = "event"
	cleaned = {}	
	
    request.session[sessid]=[table_type,object_type,display,cleaned]

    return render_to_response('home/eventssearch.html',
                              locals(),
                              context_instance=RequestContext(request))
@csrf_protect
@login_required
def binaries_unique(request):
    """
    List binaries
    """
    sessid = createSessionId(request.session._session_key)

    table_type = "content"
    object_type = "unique"
    display = ["Execution Timestamp","Path","Binary SHA1"]
    cleaned = {}

    request.session[sessid]=[table_type,object_type,display,cleaned]


    return render_to_response('home/binaries_unique.html',
                              {
                                  'sessid' : sessid,
                                  }, context_instance=RequestContext(request))

@csrf_protect
@login_required
def binariessearch(request):
    """
    Find Binaries by name or hash 
    """
    binaries_list=None
    if request.method == 'POST':
        searchform = binariesSearch(request.POST)
        if searchform.is_valid():
            cleaned = searchform.cleaned_data
            sessid = createSessionId(request.session._session_key)
            table_type = "search"
            object_type = "binary"
            display = ["Station","Path","Binary SHA1"]    
            request.session[sessid]=[table_type,object_type,display,cleaned]
    else:
        sessid = None
        searchform = binariesSearch()


    return render_to_response('home/binariessearch.html',
                              {'sessid': sessid  ,
                               'searchform':searchform,
                               }, context_instance=RequestContext(request))

@csrf_protect
@login_required
def intrusion(request):
    """
    Check for intrusion method
    """

    station_list = None
    if request.method == 'POST':
        searchform = intrusionSearch(request.POST)
        if searchform.is_valid():
            cleaned = searchform.cleaned_data
            sessid = createSessionId(request.session._session_key)
            table_type = "intrusion"
            request.session[sessid]=[table_type,None,None,cleaned]
#            display = ["Hostname","IP Address"]
#            request.session[sessid]=[table_type,object_type,display,cleaned]

    else:
        searchform = intrusionSearch()
        sessid = None


    return render_to_response('home/intrusionsearch.html',
                              {'sessid':sessid,
                               'searchform':searchform,
                               }, context_instance=RequestContext(request))




@csrf_protect
@login_required
def binaryRel(request, sid, days):
    i = 0
    relation = {}
    nodes = {}
    days = int(days)
    if days == 8888:
	evs = events.objects.all()
    else:
	evs = events.objects.filter(event_timestamp__gte = datetime.datetime.now() - timedelta( days= days ) )   
	
    for ev in evs:
        p_name = ntpath.basename(ev.parent_binary.file_path)
        if p_name == "A":
            p_name = "NA"
	else:    
	    p_name += ' %s' % ev.parent_binary.binary_sha1[-4:]
	
        c_name = "%s %s" % ( ntpath.basename(ev.binary.file_path), ev.binary.binary_sha1[-4:])
	
        if c_name not in relation:
            relation[c_name] = []
	
	if c_name not in nodes:
	    nodes[c_name] = (ev.binary.id, "node%d" % i)
	    i += 1
	    
        if p_name in relation:
            if c_name not in relation[p_name]:
                relation[p_name].append(c_name)
        else:
            relation[p_name] = []
            relation[p_name].append(c_name)
	    
	if p_name not in nodes:
	    nodes[p_name] = (ev.parent_binary.id, "node%d" % i)
	    i += 1
	    
    edges = []
    for rel in relation:
        for b in relation[rel]:
            edges.append((nodes[rel][1],nodes[b][1]))
                
    
    return render_to_response('home/binary_rel.html',
                              {"nodes" : nodes,
                               "edges" : edges,
                               "sid": sid
                               }, context_instance=RequestContext(request))

@csrf_protect
@login_required
def usbRel(request, sid, did):
    i = 0
    relation = {}
    nodes = {}
    shared = [] 
    
    #print "station id " + sid
    #print "device id " + did 
    
    #evs = usb_events.objects.all()
    evs = usb_mass_storage_events.objects.all()
    uevs = usb_events.objects.all()

    for ev in evs:
        #usb_dev_id = ev.mass_storage_device.serial_number+ev.mass_storage_device.pnp_device_id 
        usb_dev_id = ev.mass_storage_device.id 
        station_name = ev.station.hostname 
	
        if station_name not in relation:
            relation[station_name] = []
	
	if station_name not in nodes:
	    nodes[station_name] = (ev.station.id, "node%d" % i, "station", ev.station.ip_address)
	    i += 1
	    
        if usb_dev_id in relation:
            if station_name not in relation[usb_dev_id]:
                relation[usb_dev_id].append(station_name)
                shared.append(usb_dev_id)
        else:
            relation[usb_dev_id] = []
            relation[usb_dev_id].append(station_name)
	#print shared 
	if usb_dev_id not in nodes:
	    if str(ev.mass_storage_device.id) == did:
                nodes[usb_dev_id] = (ev.mass_storage_device.id, "node%d" % i, "ms_marked_device",ev.mass_storage_device.serial_number)
	    elif usb_dev_id in shared:
                nodes[usb_dev_id] = (ev.mass_storage_device.id, "node%d" % i, "ms_shared_device",ev.mass_storage_device.serial_number)
	    else:
                nodes[usb_dev_id] = (ev.mass_storage_device.id, "node%d" % i, "ms_device",ev.mass_storage_device.serial_number)
	    i += 1
        else:
	    if usb_dev_id in shared:
                tt = nodes[usb_dev_id]
                new_tt = ( tt[0], tt[1], "ms_shared_device", tt[3] )
                nodes[usb_dev_id] = new_tt 
            
    
    for uev in uevs:
        usb_dev_id = uev.device.id
        usb_dev_caption = uev.device.caption
        usb_dev_class = uev.device.usb_class
        station_name = uev.station.hostname 

        if station_name not in relation:
            relation[station_name] = []
	
	if station_name not in nodes:
	    nodes[station_name] = (uev.station.id, "node%d" % i, "station", uev.station.ip_address)
	    i += 1
	    
        if usb_dev_id in relation:
            if station_name not in relation[usb_dev_id]:
                relation[usb_dev_id].append(station_name)
        else:
            relation[usb_dev_id] = []
            relation[usb_dev_id].append(station_name)
	    
	if usb_dev_id not in nodes:
            if "mouse" in usb_dev_caption:
                dtype = "mouse" 
            elif "Keyboard" in usb_dev_caption:
                dtype = "keyboard"
            elif "6/1/1" in usb_dev_class:
                dtype = "camera"
	    else:
                dtype="device"
            
            #print usb_dev_class

            caption = usb_dev_caption 
            if "|" in caption:
                caption = usb_dev_caption[usb_dev_caption.rfind("|")+1:]
            
            nodes[usb_dev_id] = (uev.device.id, "node%d" % i, dtype ,caption)
            
	    i += 1
	    
    edges = []
    for rel in relation:
        for b in relation[rel]:
            edges.append((nodes[rel][1],nodes[b][1]))
                
    
    return render_to_response('home/usb_rel.html',
                              {"nodes" : nodes,
                               "edges" : edges,
                               "sid": sid
                               }, context_instance=RequestContext(request))

@csrf_protect
@login_required
#def usbConnTimeline(request, sid):
def usbConnTimeline(request):
    print "Timeline"
    #return HttpResponse("oops")
    return render_to_response('home/usb_timeline.html', {}
                               , context_instance=RequestContext(request))

@csrf_protect
@login_required
def eventInspection(request, sid, binid):
    
    ev = events.objects.filter(station__id = sid, parent_binary__id = binid).order_by("event_timestamp")[0]
    return render_to_response('home/event_inspection.html',
                              {"sid": sid, 
                               "binid": binid, 
                               "stationname": ev.station.hostname,
                               "binname":  ntpath.basename(ev.parent_binary.file_path)
                               },
                              context_instance=RequestContext(request))

@csrf_protect
@login_required
def json_event_graph(request, sid, binid, field):
    evs   =  events.objects.filter(station__id = sid, 
                                   parent_binary__id = binid).order_by("event_timestamp")[:10]
    all_evs = events.objects.all()
    #print field 
    #handles = [int(getattr(ev,event_types[field])) for ev in all_evs]
    handles = [int(getattr(ev,event_types[field]) if getattr(ev,event_types[field]) != "N/A" else "0") for ev in all_evs]

    mean = numpy.mean(handles)
    values = [{'x': i, 'y' : mean} for i in xrange(1,11)]
    
    data = []
    for i,ev in enumerate(evs):
	    tstamp = i+1 
	    #data.append({'x' : i+1, 'y' : int(getattr(ev,event_types[field]))}) 
	    data.append({'x' : i+1, 'y' : int(getattr(ev,event_types[field]) if getattr(ev,event_types[field]) != "N/A" else "0")}) 
	    
    response = []
    response.append({'key'    : field,
                   'values' : data,
                   'color': '#ff7f0e'
                   })
    
    response.append({'key' : 'Mean',
                   'values' : 	values,
                   'color': '#2ca02c'                    
                   })         

    #return HttpResponse(json.dumps(response), 
    #                    mimetype="application/json")
    return HttpResponse(json.dumps(response))
	    
@csrf_protect
@login_required
def JSONeventInspection(request, sid, binid):
    evs   =  events.objects.filter(station__id = sid, parent_binary__id = binid).order_by("event_timestamp")
   
    HandleCount                     = {"name": "Handle Count", "articles" : [], "total" : 0}
    ThreadCount                     = {"name": "Thread Count", "articles" : [], "total" : 0}
    VirtualSize                     = {"name": "Virtual Size", "articles" : [], "total" : 0}
    PeakVirtualSize                 = {"name": "Peak Virtual Size", "articles" : [], "total" : 0}
    Quota_Paged_Pool_Usage          = {"name": "Quota Paged Pool Usage", "articles" : [], "total" : 0}
    Quota_Non_Paged_Pool_Usage      = {"name": "Quota Non Paged Pool Usage", "articles" : [], "total" : 0}
    Quota_Peak_Paged_Pool_Usage     = {"name": "Quota Peak Paged Pool Usage", "articles" : [], "total" : 0}
    Quota_Peak_Non_Paged_Pool_Usage = {"name": "Quota Peak Non Paged Pool Usage", "articles" : [], "total" : 0}
    Read_Operation_Count            = {"name": "Read Operation Count", "articles" : [], "total" : 0}
    Write_Operation_Count           = {"name": "Write Operation Count", "articles" : [], "total" : 0}
    User_Mode_Time                  = {"name": "User Mode Time", "articles" : [], "total" : 0}
    tbl = evs[:10]
    
    ids = {}
    
    for i,ev in enumerate(tbl):
	tstamp = ev.event_timestamp.strftime("%Y-%m-%d %H:%M:%S")
	tstamp = i+1 
	ids[tstamp] = ev.id
	#tstamp = str(2002 + i)
        handle_count = int(ev.handle_count if ev.handle_count != "N/A" else "-1")
	HandleCount["articles"].append( [tstamp, handle_count ] )     
	if handle_count > 0 : 
	    HandleCount["total"] += handle_count if handle_count > 0 else 0 
        thread_count = int(ev.thread_count if ev.thread_count != "N/A" else "-1") 
        ThreadCount["articles"].append( [tstamp, thread_count ] )
	if thread_count > 0 :  	
	    ThreadCount["total"] += thread_count if thread_count > 0 else 0  	
	virtual_size = int(ev.virtual_size if ev.virtual_size != "N/A" else "-1") 
	VirtualSize["articles"].append( [tstamp, virtual_size ] )
	if virtual_size > 0 :
            VirtualSize["total"] += virtual_size 
	peak_virtual_size =  int(ev.peak_virtual_size if ev.peak_virtual_size != "N/A" else "-1")
	PeakVirtualSize["articles"].append( [tstamp, peak_virtual_size ] )
	if peak_virtual_size >  0 :
            PeakVirtualSize["total"] += peak_virtual_size 
        quota_paged_pool_usage = int(ev.quota_paged_pool_usage if ev.quota_paged_pool_usage != "N/A" else "-1") 
	Quota_Paged_Pool_Usage["articles"].append( [tstamp, quota_paged_pool_usage ] )
	if quota_paged_pool_usage > 0:
	    Quota_Paged_Pool_Usage["total"] += quota_paged_pool_usage 
	quota_peak_paged_pool_usage = int(ev.quota_peak_paged_pool_usage if ev.quota_peak_paged_pool_usage != "N/A" else "-1") 
	Quota_Peak_Paged_Pool_Usage["articles"].append( [tstamp, quota_peak_paged_pool_usage ] )
	if quota_peak_paged_pool_usage > 0:
	    Quota_Peak_Paged_Pool_Usage["total"] += quota_peak_paged_pool_usage 
	quota_non_paged_pool_usage = int(ev.quota_non_paged_pool_usage if ev.quota_non_paged_pool_usage != "N/A" else "-1" )
	Quota_Non_Paged_Pool_Usage["articles"].append( [tstamp, quota_non_paged_pool_usage ] )
	if quota_non_paged_pool_usage > 0 :
	    Quota_Non_Paged_Pool_Usage["total"] += quota_non_paged_pool_usage
	quota_peak_non_paged_pool_usage = int(ev.quota_peak_non_paged_pool_usage if ev.quota_peak_non_paged_pool_usage != "N/A" else "-1")
	Quota_Peak_Non_Paged_Pool_Usage["articles"].append( [tstamp, ev.quota_peak_non_paged_pool_usage ] )
	if quota_peak_non_paged_pool_usage > 0 :
	    Quota_Peak_Non_Paged_Pool_Usage["total"] +=  quota_peak_non_paged_pool_usage
	write_operation_count = int(ev.write_operation_count if ev.write_operation_count != "N/A" else "-1" ) 
	Write_Operation_Count["articles"].append( [tstamp, write_operation_count ] )
	if write_operation_count > 0:
	    Write_Operation_Count["total"] += write_operation_count
	user_mode_time = int(ev.user_mode_time if ev.user_mode_time != "N/A" else "-1")
	User_Mode_Time["articles"].append( [tstamp, user_mode_time ] )
	if user_mode_time > 0:
	    User_Mode_Time["total"] += user_mode_time 
    
    jslist = [HandleCount, ThreadCount, VirtualSize, PeakVirtualSize, Quota_Non_Paged_Pool_Usage, Quota_Paged_Pool_Usage, 
              Quota_Peak_Non_Paged_Pool_Usage, Quota_Peak_Paged_Pool_Usage, Write_Operation_Count, User_Mode_Time]
    
    
    trange = [tbl[0].event_timestamp.strftime("%Y-%m-%d %H:%M:%S"), tbl[len(tbl)-1].event_timestamp.strftime("%Y-%m-%d %H:%M:%S")  ]  
    #return HttpResponse(simplejson.dumps({"info":jslist, "trange": trange, 'ids' : ids} ), mimetype="application/json")
    #return HttpResponse(json.dumps({"info":jslist, "trange": trange, 'ids' : ids} ), mimetype="application/json")
    return HttpResponse(json.dumps({"info":jslist, "trange": trange, 'ids' : ids} ))

    

@csrf_protect
@login_required
def JSONbinaryRel(request, sid):  # TODO: ADD DATE LIMIT
    evs   = events.objects.all()
    jslist  = {}
    for i,ev in enumerate(evs[:50]):
        p_name = ntpath.basename(ev.parent_binary.file_path)
        if p_name == "A":
            p_name = "N/A"
	p_name += ' %s' % ev.parent_binary.binary_sha1[-4:]
	
        c_name = ntpath.basename(ev.binary.file_path)
        c_name += ' %s' % ev.binary.binary_sha1[-4:]
	
        # Child
        if c_name in jslist.keys():
            if p_name not in jslist[c_name]["depends"]:
                jslist[c_name]["depends"].append(p_name)            
        else:
            child = {}
            child["name"] = c_name
            child["depends"] = [p_name]
            child["docs"] = "Hola"
            child["type"] = ttype
            jslist[ c_name ]  = child
        
        # Parent
        if p_name not in jslist.keys():
            parent = {}
            parent["name"] = p_name
            parent["depends"] = []
            parent["type"] = ttype
            child["docs"] = "Hola2"
            jslist[p_name] = parent
    #import pprint
    #pprint.pprint(jslist)
    
    #return HttpResponse(simplejson.dumps({"data": jslist, "error":[] } ) , mimetype="application/json")
    #return HttpResponse(json.dumps({"data": jslist, "error":[] } ) , mimetype="application/json")
    return HttpResponse(json.dumps({"data": jslist, "error":[] } ))

@csrf_protect
@login_required
def JSONprocessUsage(request, sid, days): 
    from django.db.models import Count
    #.filter(event_timestamp__gte = datetime.datetime.now() - timedelta( days= days ) ) 
    days = int(days)
    if days == 8888:
	objects = events.objects.values("binary__file_path").filter(station__id = sid).order_by("binary").annotate(count= Count('binary'))
	total   = events.objects.filter(station__id = sid).count()	
    else:
	objects = events.objects.values("binary__file_path").filter(station__id = sid, event_timestamp__gte = datetime.datetime.now() - timedelta( days= days )).order_by("binary").annotate(count= Count('binary'))
	total   = events.objects.filter(station__id = sid, event_timestamp__gte = datetime.datetime.now() - timedelta( days= days ) ).count()
    
    st = """{
     "name": "flare",
     "children": [
      {
       "name": "analytics",
       "children": [
       """
    t = [] 
    a=0
    for ev in objects:
        fl = ntpath.basename(ev["binary__file_path"])
        t.append( """ 	{
	     "name": "%s",
	     "children": [
	      {"name": "%s", "size": %d}
	     ]
	     }""" % (fl, fl, 1.0/ev["count"]*10000/total ) ) 

    st+= ",".join(t) + " ]}]} "
    #print st
    #return HttpResponse(st, mimetype="application/json")
    return HttpResponse(st)

@csrf_protect
@login_required
def processUsage(request, sid, days):
    """
    Show process usage on station
    """

    return render_to_response('home/process_usage.html',
                              {"sid": sid, "days": days}, context_instance=RequestContext(request))

@csrf_protect
@login_required
def stationssearch(request):
    """
    List stations
    """

    station_list = None
    if request.method == 'POST':
        searchform = stationSearch(request.POST)
        if searchform.is_valid():
            cleaned = searchform.cleaned_data
            sessid = createSessionId(request.session._session_key)
            table_type = "search"
            object_type = "station"
            display = ["Last Seen","Hostname","IP Address"]
            request.session[sessid]=[table_type,object_type,display,cleaned]

    else:
        searchform = stationSearch()
        sessid = None


    return render_to_response('home/stationssearch.html',
                              {'sessid':sessid,
                               'searchform':searchform,
                               }, context_instance=RequestContext(request))


@csrf_protect
@login_required    
def eventsbybinary(request,command=None,sid=None):
    """  
    List of events produced by the requested binary 
    """
    if command == "events" and sid != None:

        model = events
        inputs = [] 
        for field in model._meta.fields:
            if field.name not in ['id']:
                input_dict = {} 
                input_dict['name'] = field.name
                input_dict['type'] = field.get_internal_type()
                inputs.append(input_dict)
     
        numeric_symbols = {op:op for op in ["<",">",'==','!=','<=','>=']}  

        sessid = createSessionId(request.session._session_key)
        #table_type = "viewevents"
        table_type = "vieweventsbybinary"
        object_type = "event"
        display = ["Date","Parent Binary","Binary","Cmdline","Username","Station"]
        cleaned = {} 
        request.session[sessid]=[table_type,object_type,display,sid]

        return render_to_response('home/events.html',
                                  locals(),
                                  context_instance=RequestContext(request))

    else:
        return HttpResponse("oops")

@csrf_protect
@login_required    
def stationsview(request,command=None,sid=None):
    """
    List stations
    """

    model = events
    inputs = []
    for field in model._meta.fields:
	if field.name not in ['id']:
	    input_dict = {}
	    input_dict['name'] = field.name
	    input_dict['type'] = field.get_internal_type()
	    inputs.append(input_dict)
		
    numeric_symbols = {op:op for op in ["<",">",'==','!=','<=','>=']}   	

    if command == "events" and sid != None:
	model = events
	inputs = []
	for field in model._meta.fields:
	    if field.name not in ['id']:
		input_dict = {}
		input_dict['name'] = field.name
		input_dict['type'] = field.get_internal_type()
		inputs.append(input_dict)
		
	numeric_symbols = {op:op for op in ["<",">",'==','!=','<=','>=']}   	

        sessid = createSessionId(request.session._session_key)
        table_type = "viewevents"
        object_type = "event"
        display = ["Date","Parent Binary","Binary","Cmdline","Username","Station"]
        request.session[sessid]=[table_type,object_type,display,sid]

        return render_to_response('home/events.html',
                                   locals(),
	                           context_instance=RequestContext(request))

    elif command == "binaries" and sid != None:
        sessid = createSessionId(request.session._session_key)
        table_type = "viewbinaries"
        object_type = "binary"
        display = ["Station","Path","Binary SHA1"]
        cleaned = {}

        request.session[sessid]=[table_type,object_type,display,sid]
        
        return render_to_response('home/binaries.html',
	                          locals(),
	                          context_instance=RequestContext(request))

    elif command == "processes" and sid != None:
        sessid = createSessionId(request.session._session_key)
        table_type = "viewprocesses"
        object_type = "process"
        display = ["Path","PID","CmdLine","Username"]
        cleaned = {}

        request.session[sessid]=[table_type,object_type,display,sid]


        return render_to_response('home/processes.html',
	                          locals(),
	                          context_instance=RequestContext(request))

    else:
        return HttpResponse("oops")





@csrf_protect
@login_required    
def eventsview(request,command=None,sid=None):
    """
    List stations
    """
    if command == "events" and sid != None:
        sessid = createSessionId(request.session._session_key)
        table_type = "vieweventsevents"
        object_type = "event"
        display = ["Station","Parent Binary","Binary","Username","Date"]
        cleaned = {}
        request.session[sessid]=[table_type,object_type,display,sid]

        return render_to_response('home/events.html',
                                  {'sessid': sessid  ,
                                   }, context_instance=RequestContext(request))

    elif command == "binaries" and sid != None:
        sessid = createSessionId(request.session._session_key)
        table_type = "viewbinariesevents"
        object_type = "binary"
        display = ["Station","Path","Binary SHA1"]
        cleaned = {}

        request.session[sessid]=[table_type,object_type,display,sid]


        return render_to_response('home/binaries.html',
                                  {'sessid': sessid  ,
                                   }, context_instance=RequestContext(request))
    else:
        return HttpResponse("oops")


@csrf_protect
@login_required    
def display_obj(request,object=None,sid=None):
    """
    Display all information for given object id
    """
    sessid = None
    name_base_stations=[]
    sha1_base_stations=[]
    if object == "event" and sid != None:
        event = events.objects.get(id=sid)
        tevent = event
        parent = 1
        child = 0
        eventtree_m = [event]
        eventtree_js = ["%d,%d," % (parent,child)]

        while True:
            print tevent.binary.pid
            print tevent.parent_binary.pid	    
            if tevent.binary.pid != tevent.parent_binary.pid:
                print tevent.binary.pid
                print tevent.parent_binary.pid
                tevent = events.objects.filter(binary__pid = tevent.parent_binary.pid,binary__binary_sha1 = tevent.parent_binary.binary_sha1,event_timestamp__lt = tevent.event_timestamp).order_by('-event_timestamp')
                if not tevent: break
                tevent=tevent[0]
                print tevent.binary.pid
                print tevent.parent_binary.pid		
                child = parent
                parent= parent +1
                eventtree_m.append(tevent)
                eventtree_js.append("%d,%d," % (parent,child))

            else:
                break


        eventtree_m.reverse()
        eventtree=[]
        for ev_tree in eventtree_m:
            eventtree.append((ev_tree,eventtree_js[eventtree_m.index(ev_tree)]))

        cleaned = event
        sessid = createSessionId(request.session._session_key)
        table_type = "childevent"
        object_type = "event"
        display = ["Date","Child Binary","Flags","Cmdline","Username","Station"]
        request.session[sessid]=[table_type,object_type,display,event.id]

        print eventtree
        return render_to_response('home/event_dsp.html',
                                  {'event': event  ,
                                   'eventtree':eventtree,
                                   'sessid':sessid,
                                   }, context_instance=RequestContext(request))

    elif object == "binary" and sid != None:
        binary = binaries.objects.get(id=sid)
        if CUCKOO_FOUND:
	    #report = results_db.analysis.find_one({"target.file.sha1": binary.binary_sha1}, sort=[("_id", pymongo.DESCENDING)])
	    reports = results_db.analysis.find({"target.file.sha1": binary.binary_sha1}, sort=[("_id", pymongo.DESCENDING)])
            reports_count = reports.count()
            #print "cantidad de reportes:" + str(reports_count)
            if reports_count == 1:
                report = reports.next()
            else:
                report = None
	else:
	    report = None
            reports_count = 0
        
        task_id = None
        if report:
            task_id = report['info']['id']
        

        bin_sta = binaries.objects.filter(file_path__iexact=binary.file_path).order_by('last_execution')

        if len(bin_sta) > 1:
            for nbs in bin_sta:
                name_base_stations.append(nbs.station)

        bin_sta_sha = binaries.objects.filter(binary_sha1=binary.binary_sha1).order_by('last_execution')

        if len(bin_sta_sha) > 1:
            for sbs in bin_sta_sha:
                sha1_base_stations.append(sbs.station)
 
	if CUCKOO_FOUND:

            cfg = Config()    
            machinery_name = cfg.cuckoo.machinery
            vm_conf = Config(os.path.join(CUCKOO_ROOT, "conf", "%s.conf" % machinery_name))
            options = vm_conf.get(machinery_name)
	    machines = {}  
             
            if options.get("machines"):
	        for machine_id in options.get("machines").strip().split(","):
		        machine_opts = vm_conf.get(machine_id.strip())
		        machines[machine_id]=machine_opts
            else:
                machines = None
	else:
		machines = None
		
        return render_to_response('home/binary_dsp.html',
                                  {'binary'          : binary  ,
                                   'name_base'       : name_base_stations,
                                   'sha1_base'       : sha1_base_stations,
                                   'task_id'         : task_id,
                                   'reports_count'   : reports_count,
                                   'machines'        : machines,
                                   }, context_instance=RequestContext(request))

    elif object == "station" and sid != None:
        st = stations.objects.get(id=sid)



        return render_to_response('home/station_dsp.html',
                                  {'station': st  ,
                                   }, context_instance=RequestContext(request))
    
    elif object == "device" and sid != None:
        usb_device = usb_devices.objects.get(id=sid)

        uevents = usb_events.objects.filter(device_id=sid).order_by('event_timestamp')

        if uevents:
            for ue in uevents:
                if ue.station not in name_base_stations:
                    name_base_stations.append(ue.station)

        vendor = "N/A"
        if usb_device.vendor_id.lower() in vid:
            vendor = vid[usb_device.vendor_id.lower()]

        product = "N/A"

        if vid_pid.has_key(usb_device.vendor_id.lower()):
            pids = vid_pid[usb_device.vendor_id.lower()]
            if pids.has_key(usb_device.product_id.lower()):
                product = pids[usb_device.product_id.lower()]
        
        return render_to_response('home/device_dsp.html',
                                  {'device'                   : usb_device  ,
                                   'vendor'                   : vendor  ,
                                   'product'                  : product  ,
                                   'connected_stations'       : name_base_stations,
                                   }, context_instance=RequestContext(request))
    
    elif object == "ms_device" and sid != None:
        usb_device = usb_mass_storage.objects.get(id=sid)

        uevents = usb_mass_storage_events.objects.filter(mass_storage_device_id=sid).order_by('event_timestamp')

        if uevents:
            for ue in uevents:
                if ue.station not in name_base_stations:
                    name_base_stations.append(ue.station)

        return render_to_response('home/device_dsp.html',
                                  {'device'                   : usb_device  ,
                                   'connected_stations'       : name_base_stations,
                                   }, context_instance=RequestContext(request))
    
    elif object == "usb_event" and sid != None:
        usb_event = usb_events.objects.get(id=sid)

        return render_to_response('home/usb_event_dsp.html',
                                  {'usb_event': usb_event  ,
                                   'usb_type': "other",
                                   #'sessid':sessid,
                                   }, context_instance=RequestContext(request))
    
    elif object == "usb_ms_event" and sid != None:
        usb_event = usb_mass_storage_events.objects.get(id=sid)

        return render_to_response('home/usb_event_dsp.html',
                                  {'usb_event': usb_event  ,
                                   'usb_type': "mass_storage",
                                   #'sessid':sessid,
                                   }, context_instance=RequestContext(request))


    else:
        return HttpResponse("oops")


@csrf_protect
@login_required    
def dispatch_xmlserver_logfile(request):
    """
    dispatch latest xml logfile
    """
    try:
        filename = "xml_log.txt"
        ff = HOMEDIR+"/webapp/xml_log/"+filename
        f = open(ff,'rb')
        data = f.read()
    except:
        return HttpResponse("No log file to download")

    #response = HttpResponse(data, mimetype="application/octet-stream")
    response = HttpResponse(data)
    response['Content-Disposition'] = 'inline; filename=%s' % filename
    return response




def fakeadd(request):
    st = stations(hostname="localhost",ip_address="200.200.200.245")
    st.save()

    code_section=base64.b64encode("ASDASDASDASDEQW")
    bin = binaries(file_path="esass",binary_sha1="eeeee",code_section_sha1="EEEF",station=st,code_section=code_section)
    bin.save()

    ev = events(username="trop",event_timestamp=datetime.datetime.now(),binary=bin)
    ev.save()

    return HttpResponse("Added")


@login_required
def handle_tags(request):
    action = request.GET['action']
    try:
        binary_id = int(request.GET['binary_id'])
    except:
        #return HttpResponse(json.dumps(0), mimetype="application/json")
        return HttpResponse(json.dumps(0))

    tag = request.GET['tag']    

    if not binary_id or not tag or not action:
        #return HttpResponse(json.dumps(0), mimetype="application/json")
        return HttpResponse(json.dumps(0))

    if action == 'add':
        binary = get_object_or_404(binaries,id=binary_id)  
        binary.tag.add(tag)

    if action == 'remove':
        binary = get_object_or_404(binaries,id=binary_id)  
        binary.tag.remove(tag)

    binary.save()

    #return HttpResponse(json.dumps(1), mimetype="application/json")
    return HttpResponse(json.dumps(1))

@login_required
def virustotal(request):
    """
    Given a sha2 hash of a binary parses the virustotal analysis page and
    returns wheter the binary is malware or not.
    """
    response = {}    
    binary_sha2 = request.GET['binary_sha2']
    if not binary_sha2:
        response['message'] = 'No hash provided'
        #return HttpResponseBadRequest(json.dumps(response), mimetype="application/json")
        return HttpResponseBadRequest(json.dumps(response))

    opener = urllib2.build_opener()
    opener.addheaders = [('User-agent', 'Mozilla/5.0')]
    response = opener.open('https://www.virustotal.com/en/file/%s/analysis/' % binary_sha2)
    
    data = response.read()
    if 'File not found' in data:
        #return HttpResponse(json.dumps(-1), mimetype="application/json")
        return HttpResponse(json.dumps(-1))
    
    parser = MyHTMLParser()
    parser.feed(data)
    if parser.found:
        #return HttpResponse(json.dumps(1), mimetype="application/json")
        return HttpResponse(json.dumps(1))
    else:
        #return HttpResponse(json.dumps(0), mimetype="application/json")
        return HttpResponse(json.dumps(0))

@csrf_protect
@login_required
def binary_request_add(request):		
    binary_id = request.GET['binary_id']
    
    try:
	binary_requests.objects.get(binary__id = binary_id)
	#return HttpResponseBadRequest(json.dumps("File already on queue."), 
	#                    mimetype="application/json")	
	return HttpResponseBadRequest(json.dumps("File already on queue."))

    except:
	new_binreq = binary_requests()
    
	new_binreq.binary = binaries.objects.get(id = binary_id)
	new_binreq.save()
    
    #return HttpResponse(json.dumps("Added to queue."), 
                        #mimetype="application/json")

    return HttpResponse(json.dumps("Added to queue.")) 

@login_required
def comment_setter(request):
    """
    Given a sha2 hash of a binary parses the virustotal analysis page and
    returns wheter the binary is malware or not.
    """
    response = {}    
    comment = request.GET['comment']
    binary_id = request.GET['binary']
    
    if not comment or not binary_id:
        response['message'] = 'Comment and binary are necesary'
        #return HttpResponseBadRequest(json.dumps(response), mimetype="application/json")
        return HttpResponseBadRequest(json.dumps(response))
    
    try:
	binary_id = int(binary_id)
    except:
        response['message'] = 'Binary is a numeric value'
        #return HttpResponseBadRequest(json.dumps(response), mimetype="application/json")
        return HttpResponseBadRequest(json.dumps(response))
    
    try:
	binary = binaries.objects.get(id=binary_id)
	binary.comment = comment
	binary.save()
    except:
        response['message'] = 'Binary not found'
        #return HttpResponseBadRequest(json.dumps(response), mimetype="application/json")	
        return HttpResponseBadRequest(json.dumps(response))	
    
    #return HttpResponse(json.dumps(1), mimetype="application/json")
    return HttpResponse(json.dumps(1))

@login_required
@csrf_protect
def binaries_ajax(request):
    start = int(request.GET['iDisplayStart'])
    tag_filter = request.GET['tag_filter']
    station_id = request.GET['station_id']
    
    #print "tag " + str(tag_filter)
    #print "start " + str(start)
    #print "station id " + str(station_id)

    if station_id:
        objects = binaries.objects.all().filter(station=station_id).order_by('last_execution')
        #objects = binaries.objects.all().filter(station=station_id).order_by('pid')

    if tag_filter:
        if tag_filter == 'All':
            objects = binaries.objects.all().order_by('last_execution')
        else:
            objects = binaries.objects.all().filter(tag__name__in=tag_filter.split(',')).order_by('last_execution')

    paginator = Paginator(objects, 25)
    page_number = start/25 + 1
    
    try:
        objlist = paginator.page(page_number)
    except (EmptyPage, InvalidPage):
        objlist = paginator.page(paginator.num_pages)
	
    content = []
    for binary in objlist:
        # Don't show "N/A"
        if binary.file_path == "N/A":
            continue

	item = []
	item.append('<input type="hidden" id="select_{{binary.id}}" value="%s" style="width:100%%;" />' % ','.join(binary.tag.names()))
	item.append('<a href=%s>%s</a>' % (reverse('home.views.display_obj',
	                                           args=['station',
	                                                 binary.station.id]),
	                                   binary.station.hostname))

	if 'Windows' in binary.file_path:
	    url = '<a href="%s"> <img src="/imedia/images/glyphicons_203_lock.png">%s</a>'
	else:
	    url = '<a href="%s"> <img src="/imedia/images/glyphicons_003_user.png">%s</a>'
	    
	item.append(url % (reverse('home.views.display_obj',
	                                           args=['binary',
	                                                 binary.id]),
	                                   binary.file_path))
	
	item.append('<a href=%s>%s</a>' % (reverse('home.views.display_obj',
	                                           args=['binary',
	                                                 binary.id]),
	                                   binary.binary_sha1))
	
	url = '<a href="%s">Events</a>' % reverse('home.views.eventsbybinary',
	                                           args=['events',
	                                                 binary.id])
	item.append(url)
	
	url = '<a href="https://www.virustotal.com/en/file/%s/analysis/"><img id="%s" class="eye" src="/imedia/images/glyphicons_051_eye_open.png"> </a>'
	item.append(url % (binary.binary_sha256,binary.binary_sha256))
	
	content.append(item)	
	
    result = {}
    result['iTotalRecords'] = objects.count()
    result['iTotalDisplayRecords'] = objects.count()
    
    #try:
#	result['sEcho'] = int(request.GET['sEcho'])
 #   except:
#	return HttpResponse(json.dumps({}), mimetype="application/json")
    result['aaData'] = content
    #return HttpResponse(json.dumps(result), mimetype="application/json")
    return HttpResponse(json.dumps(result))

@login_required
@csrf_protect
def cuckoo_start_analysis(request):
    binary_id = request.GET['binary_id']
    selected_vm = request.GET['selected_vm']
    #import pprint
    #pprint.pprint(selected_vm)

    if not binary_id:
        #return HttpResponseBadRequest(json.dumps('Binary id is missing.'),
	#                              mimetype="application/json")	
        return HttpResponseBadRequest(json.dumps('Binary id is missing.'))

    try:
	binary = binaries.objects.get(id=binary_id)
    except:
        return HttpResponseBadRequest(json.dumps('Invalid binary id.'))
        #return HttpResponseBadRequest(json.dumps('Invalid binary id.'),
	#                              mimetype="application/json")
    if not binary.data:
	return HttpResponseBadRequest(json.dumps('Download the file before starting the analysis.'))
	#return HttpResponseBadRequest(json.dumps('Download the file before starting the analysis.'),
	#                              mimetype="application/json")
	
    binary = binaries.objects.get(id=binary_id)
    #filename = ntpath.basename(binary.file_path) + binary.station.hostname
    #output = ntpath.join('/tmp/', filename)
    filename = ntpath.basename(binary.file_path)
    temp_file_path = "/tmp/" + binary.station.hostname + "/"
    
    if not os.path.exists(temp_file_path):
        os.makedirs(temp_file_path)
    
    output = ntpath.join(temp_file_path, filename)

    with open(output, "wb") as handle:
	handle.write(binary.data)
	
    if CUCKOO_FOUND:
	db = Database()
	tasks = db.list_tasks(status=TASK_PENDING)
	
	for task in tasks: 
	    if task.to_dict()['target'] == output:
		#return HttpResponse(json.dumps('Already added'), mimetype="application/json")    
		return HttpResponse(json.dumps('Already added'))    
	    
	task_id = db.add_path(file_path=output,
	                      package="",
	                      timeout=120,
	                      options="",
	                      priority=1,
	                      machine=selected_vm,
	                      custom="",
	                      memory=False,
	                      enforce_timeout=False,
	                      tags=None)
	if task_id:
	    #return HttpResponse(json.dumps('OK'), mimetype="application/json")    
	    return HttpResponse(json.dumps('OK'))    
	    
    return HttpResponseBadRequest(json.dumps('The cuckoo server is not running. Please start cuckoo and try again.'))
    #return HttpResponseBadRequest(json.dumps('The cuckoo server is not running. Please start cuckoo and try again.'),
    #                              mimetype="application/json")

@login_required
@csrf_protect
def download_file(request, binary_id):
    binary = get_object_or_404(binaries,id=binary_id)
    filename = ntpath.basename(binary.file_path)
    #response = HttpResponse(binary.data,mimetype="application/x-msdownload")
    response = HttpResponse(binary.data)
    response['Content-Disposition'] = 'attachment;filename=%s' % filename 
    response['Content-Length'] = len(binary.data)
    return response    	        

 
def padding_data(dummy_template, data):
	c = str(data)
	if len(dummy_template) > len(c):
		i = len(dummy_template) - len(c)
		for x in range(0,i):
			c+='\n'
	
	return c


@csrf_protect
@login_required    
def client_setup(request):
    if request.method == 'GET':
	form = ClientSettingsForm()

    else:
        form = ClientSettingsForm(request.POST)
        if form.is_valid():    
	    username = form.cleaned_data['username']
	    password = form.cleaned_data['password']
	    host = form.cleaned_data['host']
	    port = form.cleaned_data['port']

	    try:
		user = xmlusers.objects.get(username=username)
	    except:
		user = xmlusers()
		user.username = username
		user.password = password
		user.save()
		
	    return make_client(username, password, host, port)
    
    return render_to_response('home/client_setup.html',
                              locals(),
                              context_instance=RequestContext(request))	    

def make_config(username, password, host, port):
    data = b"[authentication]\n"    
    data += b"user = " + str(username) + "\n"   
    data += b"password = " + str(password) + "\n\n" 
    data += b"[log server]\n"   
    data += b"host = " + str(host) + "\n"   
    data += b"port = " + str(port) + "\n"   
    
    return data 

def make_pattern():
    data_pattern = b"[authentication]\n"    
    data_pattern += b"user = "+ "@"+ "W"*62 + "@\n" 
    data_pattern += b"password = "+ "@"+ "Z"*62 + "@\n\n"   
    data_pattern += b"[log server]\n"   
    data_pattern += b"host = @XX.XXX.XXX.XX@\n" 
    data_pattern += b"port = @YYYY@\n"  

    return data_pattern
	     
def make_client(username, password, host, port):
    cert_path = os.path.join(PROJECT_ROOT, '..' , 'xmlserver', 'certs')
    cacart_path = os.path.join(cert_path, 'cacert.pem')
    
    if not os.path.isfile(cacart_path):
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
	cname = host  # this should match the server addr
	
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
    
    cakey_path = os.path.join(cert_path,'cacert.key')
    cacert_fd = file(cacart_path,'r')
    cacert_data = cacert_fd.read()
    
    cacert_fd.close()
    
    cacert = crypto.load_certificate(crypto.FILETYPE_PEM, cacert_data)
                                     
    
    cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, 
                                   file(cakey_path,'r').read())
    
    client_key, client_cert =  createClientCert(cacert, cakey)
    #print "ckey len " + str(len(client_key)) 
    #print "ccert len " + str(len(client_cert)) 
    server_fd = file(os.path.join(cert_path, 'server.pem'),'r')
    server_cert = server_fd.read()
    server_fd.close()
    
    #
    # Replacing certs in binary file
    #

    installer_path = os.path.join(PROJECT_ROOT, '../..' , 'installer')
    ins_path = os.path.join(installer_path, 'ElJefeInstaller.exe')
    # Open installer file
    try:
	f = open(ins_path, "rb")
	s = f.read()
	f.close()
    except:
	return
    
    begin =b"-----BEGIN PRIVATE KEY-----\n"
    end=b"-----END PRIVATE KEY-----\n"
    begin_cert=b"-----BEGIN CERTIFICATE-----\n"
    end_cert=b"-----END CERTIFICATE-----\n"

    # Replacing client.pem 
    dd = b"A"*64+"\n"
    client_pem_dummy = begin_cert+dd*16+ b"A"*16+"\n"+end_cert
	
    #cert = get_key_from_cert(client_cert) 
    s = s.replace(client_pem_dummy, bytes(padding_data(client_pem_dummy,client_cert)))

    # Replacing client.key 
    dd = b"B"*64+"\n"
    client_key_dummy = begin+dd*25+ b"B"*28+"\n"+end
    
    #cert = get_key_from_cert(client_key) 
    s = s.replace(client_key_dummy, bytes(padding_data(client_key_dummy,
                                                       client_key)))
    
    # Replacing cacert.pem
    dd = b"C"*64+"\n"
    cacert_pem_dummy = begin_cert+dd*20+ b"C"*44+"\n"+end_cert

    #cert = get_key_from_cert(cacert) 
    s = s.replace(cacert_pem_dummy, bytes(padding_data(cacert_pem_dummy,
                                                       cacert_data)))
	
    # Replacing server.pem
    dd = b"D"*64+"\n"
    server_pem_dummy = begin_cert+dd*18+ b"D"*28+"\n"+end_cert
    
    #cert = get_key_from_cert(server_cert) 
    s = s.replace(server_pem_dummy, bytes(padding_data(server_pem_dummy,server_cert)))

    #
    # End replacing certs
    #

    #    
    # Begin replacing configuration data
    #    
    #    
    config_data = make_config(username,password,host,port)
    dummy_pattern = make_pattern()
    
    s = s.replace(dummy_pattern, bytes(padding_data(dummy_pattern, config_data)))
    
    #    
    # End replacing configuration data
    #    

    installer = s

    #response = HttpResponse(installer, mimetype="application/x-msdownload")
    response = HttpResponse(installer)
    ver = get_version()
    response['Content-Disposition'] = 'attachment;filename=ElJefeInstaller_%s.exe' % ver
    response['Content-Length'] = len(installer)
    
    return response    	       



@login_required
def camal_get_info(request):
    #print "get_info" 
    file_hash = request.GET['sha256']
    
    data = {'key'       : CAMAL_APIKEY, 
            'file_hash' : file_hash}
    
    r = requests.post('https://camalapi.coseinc.com/camal/files/info',
                      data = data)
    
    response = json.loads(r.text)
    #print response 
    if 'error' in response:
	return HttpResponseBadRequest(json.dumps('File not found.'))
	#return HttpResponseBadRequest(json.dumps('File not found.'),
	#                              mimetype="application/json")
    else:
	if response['sandbox'] == 'done':
	    return HttpResponse(json.dumps('Done'))
	    #return HttpResponse(json.dumps('Done'), 
	    #                    mimetype="application/json")  
	else:
	    return HttpResponse(json.dumps('Processing'))
	    #return HttpResponse(json.dumps('Processing'),
	    #                    mimetype="application/json")    
	
@login_required	    
def camal_download_report(request, file_hash):
    #print "download report" 
    data = {'key'       : CAMAL_APIKEY, 
            'file_hash' : file_hash}
    
    r = requests.post('https://camalapi.coseinc.com/camal/reports/get',
                      data = data)
    
    report = r.text
    
    #response = HttpResponse(report, mimetype="text/html")
    response = HttpResponse(report)
    response['Content-Disposition'] = 'attachment;filename=%s.html' % file_hash
    response['Content-Length'] = len(report)
    
    return response    	       

@login_required	    
def camal_upload_binary(request):
    #print "upload_binary" 
    binary_id = request.GET['binary_id']
    
    if not binary_id:
	return HttpResponseBadRequest(json.dumps('Binary id is missing.'))
	#return HttpResponseBadRequest(json.dumps('Binary id is missing.'),
	#                              mimetype="application/json")	
	
    try:
	binary = binaries.objects.get(id=binary_id)
    except:
	return HttpResponseBadRequest(json.dumps('Invalid binary id.'))
	#return HttpResponseBadRequest(json.dumps('Invalid binary id.'),
	#	                          mimetype="application/json")
    if not binary.data:
	return HttpResponseBadRequest(json.dumps('Download the file before starting the analysis.'))
	#return HttpResponseBadRequest(json.dumps('Download the file before starting the analysis.'),
	#	                          mimetype="application/json")
	    
    binary = binaries.objects.get(id=binary_id)
    filename = ntpath.basename(binary.file_path)
    temp_file_path = "/tmp/" + binary.station.hostname + "/"
	
    if not os.path.exists(temp_file_path):
	os.makedirs(temp_file_path)
	
    output = ntpath.join(temp_file_path, filename)
    
    fd = open(output, "wb")
    fd.write(binary.data)    
    fd.close()

    fd = open(output, "rb")

    data = {'key'       : CAMAL_APIKEY, 
            'is_public' : '0'}

    files = {'upload_sample': fd }
    
    r = requests.post('https://camalapi.coseinc.com/camal/files/upload',
                      data=data,
                      files=files)    
    fd.close()
    
    return HttpResponse(json.dumps('Done')) 
    #return HttpResponse(json.dumps('Done'), 
    #                    mimetype="application/json")


@csrf_protect
@login_required
def send_scanning_time(request,sid=None):		
    
    time = request.GET['time']
    
    try:
        st = stations.objects.get(id=sid)
        if st.scanning_time != time:
            st.scanning_time = time
            st.save()
	return HttpResponse(json.dumps("Done")) 
	#return HttpResponse(json.dumps("Done"), 
	#                    mimetype="application/json")	
    except:
    
        return HttpResponseBadRequest(json.dumps("Invalid time")) 
        #return HttpResponseBadRequest(json.dumps("Invalid time"), 
        #                mimetype="application/json")
    
