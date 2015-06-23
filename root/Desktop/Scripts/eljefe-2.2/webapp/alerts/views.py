from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseServerError, Http404, HttpResponseBadRequest
from django.shortcuts import render_to_response, get_object_or_404, redirect
from django.template import Context, loader, RequestContext
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from django.core import serializers
from alerts.forms import *
from alerts.models import *
import string
import random
import inspect
import alerts 

filters = {}
filters['%s' % ExecutionFilter()] = ExecutionFilter
filters['%s' % TestFilter()] = TestFilter

@csrf_protect        
@login_required
def add_filter(request):
    filter_forms = {}
    filter_forms['%s' % ExecutionFilter()] = ExecutionFilterForm
    filter_forms['%s' % TestFilter()] = TestFilterForm    

    if request.method == "POST":
        form = filter_forms[request.POST['selectbasic']](request.POST)
        if form.is_valid():
            form.save()
    else:
        pass
    
    return render_to_response('alerts/add.html',
                              locals(),
                              context_instance=RequestContext(request))
@csrf_protect        
@login_required
def list_filters(request):
    filter_list = {}
    
    for flt in filters:
        filter_list['%s' % flt] = (filters[flt].objects.all(), 
                                   get_filter_fields(filters[flt])
                                   )
    
    return render_to_response('alerts/list.html',
                              locals(),
                              context_instance=RequestContext(request))

@csrf_protect        
@login_required
def export_filters(request):
    if request.method == "GET":
        data = {}
        ids = request.GET.getlist('filter_ids[]', None)
        filter_type = request.GET.get('filter_type', None)
        if not ids or not filter_type:
            raise Http404
        
        model_data = filters[filter_type].objects.filter(id__in=map(int, ids))            
        

        serialized_data = serializers.serialize("json", model_data)
        serialized_data += filter_type
        
        response = HttpResponse(serialized_data,mimetype="application/octet-stream")
        response['Content-Disposition'] = 'attachment;filename=data.json' 
        response['Content-Length'] = len(serialized_data)
        
        return response
        
@csrf_protect        
@login_required
def import_selected_filters(request):
    if request.method == "GET":
        data = {}
        
        ids = request.GET.getlist('filter_ids[]', None)
        filename = request.GET.get('filename', None)
        if not ids or not filename:
            raise Http404
        
        int_ids = map(int, ids)
        data = file('/tmp/%s' % filename,'r').read()
        
        objects = []
        separator = data.rfind(']') + 1
         
        filter_type = data[separator:]
        serialized_obj = data[:separator]

        for obj in serializers.deserialize("json", serialized_obj):
            if obj.object.id in int_ids:
                last_id = obj.object.__class__.objects.latest('id').id
                obj.object.id = last_id + 1
                obj.save()
                
        return redirect('alerts.views.list_filters')
    else:
        raise Http404
    
@csrf_protect        
@login_required
def import_filters(request):
    if request.method == 'POST':
        form = ImportForm(request.POST, request.FILES)
        if form.is_valid():
            data = ""
            filename, data = handle_uploaded_file(request.FILES['file'])
                        
            objects = []
            separator = data.rfind(']') + 1
            
            filter_type = data[separator:]
            serialized_obj = data[:separator]

            deserialized_obj = serializers.deserialize("json", serialized_obj)
            for obj in deserialized_obj:
                objects.append(obj.object)

            field_names = get_filter_fields(filters[filter_type])
                                                
            return render_to_response('alerts/imports_expand.html',
                                      locals(),
                                      context_instance=RequestContext(request))                

    else:
        form = ImportForm()
        
    return render_to_response('alerts/import.html',
                              locals(),
                              context_instance=RequestContext(request))

def get_filter_fields(flt):
    fields = flt._meta.get_all_field_names()
    fields.remove('id')
    fields.remove('actions')
    
    return fields
        
def handle_uploaded_file(f):
    data = ""
    characters = string.ascii_uppercase + string.digits
    filename = ''.join(random.choice(characters) for _ in range(8))
    with open('/tmp/%s' % filename , 'wb+') as destination:
        for chunk in f.chunks():
            data += chunk
            destination.write(chunk)    
            
    return filename, data
