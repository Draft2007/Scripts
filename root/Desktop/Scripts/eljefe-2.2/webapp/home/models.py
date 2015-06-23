from django.db import models
from django.db.models import signals
from django.contrib.auth.models import User
from taggit.managers import TaggableManager
from django.contrib import admin

NOTES="""
stations is the main model.
binaries includes the foreignkey stations.
events includes the foreignkey binaries.

having that model structure, you can reach station via an event,
for example:


ev = events()
bin = ev.binary
station = bin.station
hostname = station.hostname

"""


class xmlusers(models.Model):
    username = models.CharField(max_length=64)
    password = models.CharField(max_length=64)

    def __unicode__(self):
        return u"XML Users"

    
class stations(models.Model):
    hostname = models.CharField(max_length=256)
    ip_address = models.CharField(max_length=64)
    uuid = models.CharField(max_length=64)
    last_seen = models.DateTimeField()
    certificate = models.CharField(max_length=2048)
    scanning_time = models.DecimalField(max_digits=5, decimal_places=1,default=100.0)
    
    def __unicode__(self):
        return self.hostname
    
class binaries(models.Model):
    file_path = models.CharField(max_length=512)
    binary_sha1 = models.CharField(max_length=40)
    binary_sha256 = models.CharField(max_length=64)
    binary_md5 = models.CharField(max_length=32)
    code_section_sha1 = models.CharField(max_length=40)
    station = models.ForeignKey(stations)
    comment = models.CharField(max_length=1024,default="")
#   assembly = models.TextField()
    code_section = models.TextField()
    filesize = models.CharField(max_length=40)
    entropy = models.FloatField()
    pid = models.CharField(max_length=20)
    arch = models.CharField(max_length=64)
    tag = TaggableManager()
    data = models.BinaryField(blank=True, null=True)
    last_execution = models.DateTimeField(blank = True, null = True)
    
    def __unicode__(self):
        return self.file_path + ' on ' + self.station.hostname

class privileges(models.Model):
    name = models.CharField(max_length=64)
    desc = models.TextField(max_length=5000)
    
    def __unicode__(self):
        return self.name
        

class events(models.Model):
    username = models.CharField(max_length=64)
    event_timestamp = models.DateTimeField()
    binary = models.ForeignKey(binaries,related_name='bin')
    parent_binary = models.ForeignKey(binaries,related_name='parent_bin')
    station = models.ForeignKey(stations,related_name="stations_id")
    privileges = models.ManyToManyField(privileges)
    cmdline = models.TextField()
    flags = models.TextField()
    creation_class_name = models.TextField()   
    cs_creation_class_name = models.TextField()
    cs_name = models.TextField()              
    handle  = models.CharField(max_length=16)              
    handle_count = models.CharField(max_length=16)          
    kernel_mode_time = models.FloatField()     
    user_mode_time = models.FloatField()       
    working_set_size = models.CharField(max_length=16) 
    max_working_set_size = models.CharField(max_length=16)            
    min_working_set_size = models.CharField(max_length=16)           
    os_creation_class_name =  models.TextField()			
    os_name =  models.TextField()							
    windows_version =  models.TextField()					
    other_operation_count =  models.TextField()			
    other_transfer_count =  models.TextField()			
    page_faults	= models.CharField(max_length=16)					
    page_file_usage = models.CharField(max_length=16)					
    peak_page_file_usage = models.CharField(max_length=16)			
    peak_virtual_size = models.CharField(max_length=16)				
    peak_working_set_size = models.CharField(max_length=16)			
    priority = models.CharField(max_length=16)						
    private_page_count	= models.CharField(max_length=16)			
    quota_non_paged_pool_usage = models.CharField(max_length=16)		
    quota_paged_pool_usage = models.CharField(max_length=16)			
    quota_peak_non_paged_pool_usage = models.CharField(max_length=16)	
    quota_peak_paged_pool_usage = models.CharField(max_length=16)		
    read_operation_count = models.CharField(max_length=16)			
    read_transfer_count = models.CharField(max_length=16)				
    write_operation_count = models.CharField(max_length=16)			
    write_transfer_count = models.CharField(max_length=16)			
    session_id	=  models.TextField() 					
    thread_count = models.CharField(max_length=16)					
    virtual_size = models.CharField(max_length=16)					


    def __unicode__(self):
        return u"Events"
   
class running_processes(models.Model):
    username = models.CharField(max_length=64)
    creation_date = models.DateTimeField()
    binary = models.ForeignKey(binaries,related_name='proc_bin')
    parent_binary = models.ForeignKey(binaries,related_name='proc_parent_bin')
    station = models.ForeignKey(stations,related_name="proc_stations_id")
    ppid = models.CharField(max_length=20)
    pid = models.CharField(max_length=20)
    privileges = models.ManyToManyField(privileges)
    cmdline = models.TextField()
    flags = models.TextField()
    creation_class_name = models.TextField()   
    cs_creation_class_name = models.TextField()
    cs_name = models.TextField()              
    handle  = models.CharField(max_length=16)              
    handle_count = models.CharField(max_length=16)          
    kernel_mode_time = models.FloatField()     
    user_mode_time = models.FloatField()       
    working_set_size = models.CharField(max_length=16) 
    max_working_set_size = models.CharField(max_length=16)            
    min_working_set_size = models.CharField(max_length=16)           
    os_creation_class_name =  models.TextField()			
    os_name =  models.TextField()							
    windows_version =  models.TextField()					
    other_operation_count =  models.TextField()			
    other_transfer_count =  models.TextField()			
    page_faults	= models.CharField(max_length=16)					
    page_file_usage = models.CharField(max_length=16)					
    peak_page_file_usage = models.CharField(max_length=16)			
    peak_virtual_size = models.CharField(max_length=16)				
    peak_working_set_size = models.CharField(max_length=16)			
    priority = models.CharField(max_length=16)						
    private_page_count	= models.CharField(max_length=16)			
    quota_non_paged_pool_usage = models.CharField(max_length=16)		
    quota_paged_pool_usage = models.CharField(max_length=16)			
    quota_peak_non_paged_pool_usage = models.CharField(max_length=16)	
    quota_peak_paged_pool_usage = models.CharField(max_length=16)		
    read_operation_count = models.CharField(max_length=16)			
    read_transfer_count = models.CharField(max_length=16)				
    write_operation_count = models.CharField(max_length=16)			
    write_transfer_count = models.CharField(max_length=16)			
    session_id	=  models.TextField() 					
    thread_count = models.CharField(max_length=16)					
    virtual_size = models.CharField(max_length=16)					
    log_date = models.DateTimeField()

    def __unicode__(self):
        return u"Running Processes"

class unique_executions(models.Model):
    hash = models.CharField(max_length=512)
    binary = models.ForeignKey(binaries,related_name='unique_bin')
    event = models.ForeignKey(events)
    first_run = models.DateTimeField()

class binary_requests(models.Model):
    binary = models.OneToOneField(binaries)
    
class sandbox_queue(models.Model):
    binary = models.OneToOneField(binaries)
   
class usb_devices(models.Model):
    last_connection = models.DateTimeField()
    vendor_id = models.TextField()
    product_id = models.TextField()
    usb_class = models.TextField()
    caption = models.TextField()
    
class usb_mass_storage(models.Model):
    last_connection = models.DateTimeField()
    caption = models.TextField()
    bytes_per_sector = models.CharField(max_length=16)
    capabilities = models.CharField(max_length=16)
    capability_descriptions = models.CharField(max_length=128)
    caption = models.TextField()
    config_manager_error_code = models.CharField(max_length=8)
    config_manager_user_config = models.CharField(max_length=8)
    creation_class_name = models.TextField()
    description = models.TextField()
    dev_id = models.TextField()
    firmware_revision = models.TextField()
    index = models.CharField(max_length=4)
    interface_type = models.TextField()
    manufacturer = models.TextField()
    media_loaded = models.CharField(max_length=8)
    media_type = models.TextField()
    model = models.TextField()
    name = models.TextField()
    partitions = models.CharField(max_length=8)
    pnp_device_id = models.TextField()
    sectors_per_track= models.CharField(max_length=16)
    serial_number = models.TextField()
    signature = models.TextField()
    size = models.CharField(max_length=32)
    status = models.CharField(max_length=8)
    system_creation_class_name = models.TextField()
    system_name = models.TextField()
    total_cylinders = models.CharField(max_length=16)
    total_heads = models.CharField(max_length=16)
    total_sectors = models.CharField(max_length=16)
    total_tracks = models.CharField(max_length=16)

class usb_events(models.Model):
    event_timestamp = models.DateTimeField()
    status = models.TextField()
    station = models.ForeignKey(stations,related_name="station_id")
    device = models.ForeignKey(usb_devices,related_name='usb_device_id')

class usb_mass_storage_events(models.Model):
    event_timestamp = models.DateTimeField()
    status = models.TextField()
    station = models.ForeignKey(stations,related_name="st_id")
    mass_storage_device = models.ForeignKey(usb_mass_storage,related_name='usb_mass_storage_dev_id')
    logical_drive = models.CharField(max_length=4)
    volume_serial_number = models.CharField(max_length=128)

    def __unicode__(self):
        return u"USB Events"


admin.site.register(stations)
admin.site.register(binary_requests)

