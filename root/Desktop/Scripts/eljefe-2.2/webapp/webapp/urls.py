from django.conf.urls import patterns, include, url
from django.conf import settings
import django.views.static
from django.views.generic import RedirectView
from django.contrib import admin

from settings import MEDIA_ROOT

admin.autodiscover()

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('',

    (r'^$', RedirectView.as_view(url='/home')),
    (r'^home/',include('home.urls')),
    (r'^alerts/',include('alerts.urls')),
    
    url(r"^analysis/", include("analysis.urls")),
    url(r"^file/(?P<category>\w+)/(?P<object_id>\w+)/$", "analysis.views.file"),
    (r'^admin/doc/', include('django.contrib.admindocs.urls')),
    (r'^accounts/login/$', 'django.contrib.auth.views.login', {'template_name': 'home/login.html'}),
    (r'^accounts/logout/$', 'django.contrib.auth.views.logout', {'next_page': '/'}),
    (r'^accounts/$', 'django.contrib.auth.views.login', {'template_name': 'home/login.html'}),
    (r'^admin/', include(admin.site.urls)),
)


urlpatterns += patterns('django.views',
                      (r'^imedia/(.*)$', 'static.serve', {'document_root': MEDIA_ROOT}),
                      )
 