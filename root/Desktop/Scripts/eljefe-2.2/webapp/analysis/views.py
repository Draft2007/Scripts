# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys
import re
import os

from django.conf import settings
from django.template import RequestContext
from django.http import HttpResponse
from django.shortcuts import render_to_response, redirect
from django.views.decorators.http import require_safe
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required

import pymongo
from bson.objectid import ObjectId
from django.core.exceptions import PermissionDenied
from gridfs import GridFS

if settings.CUCKOO_FOUND:
    sys.path.append(settings.CUCKOO_PATH)
    
    from lib.cuckoo.core.database import Database, TASK_PENDING
    from lib.cuckoo.common.constants import CUCKOO_ROOT
    from lib.cuckoo.common.config import Config
    from lib.cuckoo.common.objects import Dictionary

    results_db = pymongo.connection.Connection(settings.MONGO_HOST, settings.MONGO_PORT).cuckoo
    fs = GridFS(results_db)

@require_safe
@csrf_protect
@login_required
def remove_pending(request):
    db = Database()    
    tasks = db.list_tasks(status=TASK_PENDING)
    for task in tasks:
        db.delete_task(task.id)
        
    return redirect("analysis.views.pending")

@require_safe
@csrf_protect
@login_required
def index(request):
    db = Database()
    tasks_files = db.list_tasks(limit=50, category="file", not_status=TASK_PENDING)
    tasks_urls = db.list_tasks(limit=50, category="url", not_status=TASK_PENDING)

    analyses_files = []
    analyses_urls = []
    ##import pprint

    if tasks_files:
        for task in tasks_files:
            new = task.to_dict()
            new["sample"] = db.view_sample(new["sample_id"]).to_dict()
            if db.view_errors(task.id):
                new["errors"] = True

            # obtain station and file name with target
            filepath = new["target"]
            filedata = filepath.split('/')
            new["file"] = filedata[3] if len(filedata) > 3 else filedata[2]
            new["station"] = filedata[2] if len(filedata) > 3 else ""
            analyses_files.append(new)

    if tasks_urls:
        for task in tasks_urls:
            new = task.to_dict()

            if db.view_errors(task.id):
                new["errors"] = True

            analyses_urls.append(new)

    #pprint.pprint(analyses_files[0])
    return render_to_response("analysis/index.html",
                              {"files": analyses_files, "urls": analyses_urls},
                              context_instance=RequestContext(request))

@require_safe
@csrf_protect
@login_required
def pending(request):
    db = Database()
    tasks = db.list_tasks(status=TASK_PENDING)

    pending = []
    for task in tasks:
        pending.append(task.to_dict())

    return render_to_response("analysis/pending.html",
                              {"tasks" : pending},
                              context_instance=RequestContext(request))

@require_safe
@csrf_protect
@login_required
def chunk(request, task_id, pid, pagenum):
    try:
        pid, pagenum = int(pid), int(pagenum)-1
    except:
        raise PermissionDenied

    if request.is_ajax():
        record = results_db.analysis.find_one(
            {
                "info.id": int(task_id),
                "behavior.processes.process_id": pid
            },
            {
                "behavior.processes.process_id": 1,
                "behavior.processes.calls": 1
            }
        )

        if not record:
            raise PermissionDenied

        process = None
        for pdict in record["behavior"]["processes"]:
            if pdict["process_id"] == pid:
                process = pdict

        if not process:
            raise PermissionDenied

        objectid = process["calls"][pagenum]
        chunk = results_db.calls.find_one({"_id": ObjectId(objectid)})

        return render_to_response("analysis/behavior/_chunk.html",
                                  {"chunk": chunk},
                                  context_instance=RequestContext(request))
    else:
        raise PermissionDenied

@require_safe
@csrf_protect
@login_required
def report(request, task_id):
    report = results_db.analysis.find_one({"info.id": int(task_id)}, sort=[("_id", pymongo.DESCENDING)])
    #import pprint
    #pprint.pprint(report['target'])
    #pprint.pprint(report['info'])
    
    if not report:
        return render_to_response("error.html",
                                  {"error" : "The specified analysis does not exist"},
                                  context_instance=RequestContext(request))

    return render_to_response("analysis/report.html",
                              {"analysis": report},
                              context_instance=RequestContext(request))

@require_safe
@csrf_protect
@login_required
def drop_report(request,task_id):
    """ 
    delete report and task
    """ 
    report = results_db.analysis.remove({"info.id": int(task_id)})
    
    if not report:
        db = Database()
        r = db.delete_task(task_id)
    
    return index(request) 

@require_safe
@csrf_protect
@login_required
def drop_report_from_binary(request,task_id,binary_sha1):
    """ 
    delete report and task
    """ 
    report = results_db.analysis.remove({"info.id": int(task_id)})
    
    if not report:
        db = Database()
        r = db.delete_task(task_id)
    
    return show_reports(request,binary_sha1) 

@require_safe
@csrf_protect
@login_required
def drop_all(request):
    """  
    Drop all tasks and reports!
    """
    # all foreign objects are deleted aswell
    #db = Database()
    #db.delete_task("27")
    #db.delete_task("26")
    #db.delete_task("29")
    #status = db.dropall_tasks()    
    #report_list = results_db.analysis.drop()
    #import pprint
    #pprint.pprint(status)

    return render_to_response("analysis/index.html",
                              {    
                                  }, context_instance=RequestContext(request))

@require_safe
@csrf_protect
@login_required
def file(request, category, object_id):
    file_object = results_db.fs.files.find_one({"_id": ObjectId(object_id)})

    if file_object:
        content_type = file_object.get("contentType", "application/octet-stream")
        file_item = fs.get(ObjectId(file_object["_id"]))

        file_name = file_item.sha256
        if category == "pcap":
            file_name += ".pcap"
        elif category == "screenshot":
            file_name += ".jpg"
        else:
            file_name += ".bin"

        response = HttpResponse(file_item.read(), content_type=content_type)
        response["Content-Disposition"] = "attachment; filename={0}".format(file_name)

        return response
    else:
        return render_to_response("error.html",
                                  {"error": "File not found"},
                                  context_instance=RequestContext(request))

@csrf_protect
@login_required
def search(request):
    if "search" in request.POST:
        error = None

        try:
            term, value = request.POST["search"].strip().split(":", 1)
        except ValueError:
            term = ""
            value = request.POST["search"].strip()

        if term:
            # Check on search size.
            if len(value) < 3:
                return render_to_response("analysis/search.html",
                                          {"analyses": None,
                                           "term": request.POST["search"],
                                           "error": "Search term too short, minimum 3 characters required"},
                                          context_instance=RequestContext(request))

            # Search logic.
            if term == "name":
                records = results_db.analysis.find({"target.file.name": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "type":
                records = results_db.analysis.find({"target.file.type": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "ssdeep":
                records = results_db.analysis.find({"target.file.ssdeep": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "crc32":
                records = results_db.analysis.find({"target.file.crc32": value}).sort([["_id", -1]])
            elif term == "file":
                records = results_db.analysis.find({"behavior.summary.files": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "key":
                records = results_db.analysis.find({"behavior.summary.keys": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "mutex":
                records = results_db.analysis.find({"behavior.summary.mutexes": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "domain":
                records = results_db.analysis.find({"network.domains.domain": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "ip":
                records = results_db.analysis.find({"network.hosts": value}).sort([["_id", -1]])
            elif term == "signature":
                records = results_db.analysis.find({"signatures.description": {"$regex" : value, "$options" : "-1"}}).sort([["_id", -1]])
            else:
                return render_to_response("analysis/search.html",
                                          {"analyses": None,
                                           "term": request.POST["search"],
                                           "error": "Invalid search term: %s" % term},
                                          context_instance=RequestContext(request))
        else:
            if re.match(r"^([a-fA-F\d]{32})$", value):
                records = results_db.analysis.find({"target.file.md5": value}).sort([["_id", -1]])
            elif re.match(r"^([a-fA-F\d]{40})$", value):
                records = results_db.analysis.find({"target.file.sha1": value}).sort([["_id", -1]])
            elif re.match(r"^([a-fA-F\d]{64})$", value):
                records = results_db.analysis.find({"target.file.sha256": value}).sort([["_id", -1]])
            elif re.match(r"^([a-fA-F\d]{128})$", value):
                records = results_db.analysis.find({"target.file.sha512": value}).sort([["_id", -1]])
            else:
                return render_to_response("analysis/search.html",
                                          {"analyses": None,
                                           "term": None,
                                           "error": "Unable to recognize the search syntax"},
                                          context_instance=RequestContext(request))

        # Get data from cuckoo db.
        db = Database()
        analyses = []

        for result in records:
            new = db.view_task(result["info"]["id"])

            if not new:
                continue

            new = new.to_dict()

            if result["info"]["category"] == "file":
                if new["sample_id"]:
                    sample = db.view_sample(new["sample_id"])
                    if sample:
                        new["sample"] = sample.to_dict()

            analyses.append(new)

        return render_to_response("analysis/search.html",
                                  {"analyses": analyses,
                                   "term": request.POST["search"],
                                   "error": None},
                                  context_instance=RequestContext(request))
    else:
        return render_to_response("analysis/search.html",
                                  {"analyses": None,
                                   "term": None,
                                   "error": None},
                                  context_instance=RequestContext(request))

@csrf_protect
@login_required
def submit(request):
    if request.method == "POST":
        package = request.POST.get("package", "")
        timeout = force_int(request.POST.get("timeout"))
        options = request.POST.get("options", "")
        priority = force_int(request.POST.get("priority"))
        machine = request.POST.get("machine", "")
        custom = request.POST.get("custom", "")
        memory = bool(request.POST.get("memory", False))
        enforce_timeout = bool(request.POST.get("enforce_timeout", False))
        tags = request.POST.get("tags", None)

        if request.POST.get("free"):
            if options:
                options += "&"
            options += "free=yes"

        if request.POST.get("process_memory"):
            if options:
                options += "&"
            options += "procmemdump=yes"


        if request.FILES["sample"].size > settings.MAX_UPLOAD_SIZE:
            return render_to_response("error.html",
                                      {"error": "You uploaded a file that exceeds that maximum allowed upload size."},
                                      context_instance=RequestContext(request))

        path = request.FILES["sample"].temporary_file_path()
        
        db = Database()

        task_id = db.add_path(file_path=path,
                              package=package,
                              timeout=timeout,
                              options=options,
                              priority=priority,
                              machine=machine,
                              custom=custom,
                              memory=memory,
                              enforce_timeout=enforce_timeout,
                              tags=tags)

        if task_id:
            return render_to_response("success.html",
                                      {"message": "The analysis task was successfully added with ID {0}.".format(task_id)},
                                      context_instance=RequestContext(request))
        else:
            return render_to_response("error.html",
                                      {"error": "Error adding task."},
                                      context_instance=RequestContext(request))

    else:
        files = os.listdir(os.path.join(settings.CUCKOO_PATH, "analyzer", "windows", "modules", "packages"))

        packages = []
        for name in files:
            name = os.path.splitext(name)[0]
            if name == "__init__":
                continue

            packages.append(name)

        return render_to_response("analysis/submit.html",
                                  {"packages": sorted(packages)},
                                  context_instance=RequestContext(request))
    
def force_int(value):
    try:
        value = int(value)
    except:
        value = 0
    finally:
        return value  

@csrf_protect
@login_required
def vm_conf(request):
    
    cfg = Config()    
    machinery_name = cfg.cuckoo.machinery
    vm_conf = Config(os.path.join(CUCKOO_ROOT, "conf", "%s.conf" % machinery_name))
    options = vm_conf.get(machinery_name)
    machines = [] 
   
    #pprint.pprint(options)
    if options.get("machines"):
        for machine_id in options.get("machines").strip().split(","):
            machine_opts = vm_conf.get(machine_id.strip())
            machine = Dictionary()
            machine.id = machine_id.strip()
            machine.label = machine_opts["label"]
            machine.platform = machine_opts["platform"]
            machine.tags = machine_opts.get("tags", None)
            machine.ip = machine_opts["ip"]
            machine.snapshot = machine_opts.get("snapshot", None) 
            machines.append(machine)
    else:
        machines = None
    
    return render_to_response("analysis/vm_conf.html",
                              {"machines": machines,
                               "options": options,
                               "machinery": machinery_name},
                              context_instance=RequestContext(request))

@require_safe
@csrf_protect
@login_required
def show_reports(request,binary_sha1):

    db = Database()
    tasks_files = db.list_tasks_by_binary( binary_sha1, limit=50, category="file" )
    analyses_files = []
    
    if tasks_files:
        for tup in tasks_files:
            sample = tup[0] 
            task = tup[1] 
            new = task.to_dict()
            #new["sample"] = db.view_sample(new["sample_id"]).to_dict()
            new["sample"] = sample.to_dict()
            if db.view_errors(task.id):
                new["errors"] = True

            # obtain station and file name with target
            filepath = new["target"]
            filedata = filepath.split('/')
            new["file"] = filedata[3] if len(filedata) > 3 else filedata[2]
            new["station"] = filedata[2] if len(filedata) > 3 else ""
            analyses_files.append(new)

    return render_to_response("analysis/show_reports.html",
                              {"files": analyses_files, "urls": None},
                              context_instance=RequestContext(request))
