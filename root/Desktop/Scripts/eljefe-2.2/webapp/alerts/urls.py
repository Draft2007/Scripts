# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import patterns, url

urlpatterns = patterns("",                       
    url(r"^$", "alerts.views.list_filters"),
    url(r"^add/$", "alerts.views.add_filter"),
    url(r"^export/$", "alerts.views.export_filters"),
    url(r"^import/$", "alerts.views.import_filters"),
    url(r"^import_selected/$", "alerts.views.import_selected_filters"),
    
)
