from django.conf.urls import patterns

urlpatterns = patterns('home.views',
    (r"^$","firstpage"),

    (r"^stations/search","stationssearch"),
    (r"^events/search","eventssearch"),
    (r"^usb_events/search","usb_search"),    
    (r"^binaries/search","binariessearch"),
    (r"^binaries/unique","binaries_unique"),
    (r"^binary/request","binary_request_add"),
    (r"^data/dropall","dropall"),
    
    (r"^stations/scanning_time/(?P<sid>[0-9a-f]+)","send_scanning_time"),
    (r"^stations/view/(?P<command>\w+)/(?P<sid>[0-9a-f]+)","stationsview"),
    (r"^events/view/(?P<command>\w+)/(?P<sid>[0-9a-f]+)","eventsview"),
    (r"^binaries/view/(?P<command>\w+)/(?P<sid>[0-9a-f]+)","eventsbybinary"),
    (r"^display/(?P<object>\w+)/(?P<sid>[0-9a-f]+)","display_obj"),
    (r"^stations","stations_page"),
    (r"^events","events_page"),
    (r"^tag_handlder","handle_tags"),    
    (r"^malware_check","virustotal"),    
    (r"^set_comment","comment_setter"),  
    (r"^binaries_ajax","binaries_ajax"),
    
    (r"^camal_download_report/([A-Za-z0-9]+)/$","camal_download_report"),    
    (r"^camal_get_info","camal_get_info"),
    (r"^camal_upload_binary","camal_upload_binary"),
    
    (r"^json_event_graph/([0-9a-f]+)/([0-9a-f]+)/([,A-Za-z0-9_\s=.\[\]]+)/$","json_event_graph"),
        
    (r"^start_analysis","cuckoo_start_analysis"),
    
    (r"^download_client","client_setup"),
    (r"^download/([0-9]+)","download_file"),   

    (r"^binary_filter/([0-9]+)/$","binary_filter"),    
    (r"^binaries/(\d+)/([,A-Za-z0-9_\s=\[\]]+)/$","binaries_page"),
    
    (r'^content/(?P<sessid>[0-9a-f]+)$', 'requestContent'),
    (r'^content/(?P<sessid>[0-9a-f]+)/page(?P<page>[0-9]+)$', 'requestContent'),
    
    (r'^usb_content/(?P<sessid>[0-9a-f]+)$', 'requestUSBContent'),
    (r'^usb_content/(?P<sessid>[0-9a-f]+)/page(?P<page>[0-9]+)$', 'requestUSBContent'),
    
    (r"^dispatch/log","dispatch_xmlserver_logfile"),
    (r"^intrusion/","intrusion"),
    (r"^graphs/process_usage/(?P<sid>[0-9a-f]+)/(?P<days>[0-9a-f]+)","processUsage"),    
    (r"^graphs/binary_rel/(?P<sid>[0-9a-f]+)/(?P<days>[0-9a-f]+)","binaryRel"),
    (r"^graphs/usb_rel/(?P<sid>[0-9a-f]+)/(?P<did>[0-9a-f]+)","usbRel"),
    (r"^graphs/event_inspection/(?P<sid>[0-9a-f]+)/(?P<binid>[0-9a-f]+)","eventInspection"),
    (r"^json/process_usage/(?P<sid>[0-9a-f]+)/(?P<days>[0-9a-f]+)","JSONprocessUsage"),
    (r"^json/binary_rel/(?P<sid>[0-9a-f]+)","JSONbinaryRel"),    
    (r"^json/event_inspection/(?P<sid>[0-9a-f]+)/(?P<binid>[0-9a-f]+)","JSONeventInspection"),    
    (r"^usbConnTimeline","usbConnTimeline")
    
)
