# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import patterns, url

urlpatterns = patterns("",
    url(r"^$", "analysis.views.index"),
    url(r"^(?P<task_id>\d+)/$", "analysis.views.report"),
    url(r"^chunk/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<pagenum>\d+)/$", "analysis.views.chunk"),
    url(r"^vm_conf/$", "analysis.views.vm_conf"),
    url(r"^search/$", "analysis.views.search"),
    url(r"^pending/$", "analysis.views.pending"),
    url(r"^remove_pending/$", "analysis.views.remove_pending"),    
    url(r"^submit/$", "analysis.views.submit"),
    url(r"^drop_all/$", "analysis.views.drop_all"),
    url(r"^drop_report/(?P<task_id>\d+)$", "analysis.views.drop_report"),
    url(r"^drop_report_from_binary/(?P<task_id>\d+)/(?P<binary_sha1>[0-9a-f]+)$", "analysis.views.drop_report_from_binary"),
    url(r"^show_reports/(?P<binary_sha1>[0-9a-f]+)$", "analysis.views.show_reports"),
)
