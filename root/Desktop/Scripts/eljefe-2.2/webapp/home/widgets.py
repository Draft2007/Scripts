# -*- coding: utf-8 -*-
# widgets.py
#
# To use you have to put calendar/ (from http://www.dynarch.com/projects/calendar/)
# to your MEDIA folder and then include such links on your page:
# <!-- calendar -->
# <link rel="stylesheet" type="text/css" href="{{ MEDIA_URL }}calendar/calendar-win2k-cold-2.css" />
#<script type="text/javascript" src="{{ MEDIA_URL }}calendar/calendar.js"></script>
# <!-- this is translation file - choose your language here -->
#<script type="text/javascript" src="{{ MEDIA_URL }}calendar/lang/calendar-pl.js"></script>
#<script type="text/javascript" src="{{ MEDIA_URL }}calendar/calendar-setup.js"></script>
#<!-- /calendar -->

from django.utils.encoding import force_unicode
from django.conf import settings
#from django import newforms as forms
from django import forms
from datetime import datetime, time
from django.utils.safestring import mark_safe
from django.core.urlresolvers import reverse
from django.forms.util import ErrorList, ValidationError
from django.utils import formats
import datetime
import time


# DATETIMEWIDGET
calbtn = u"""<img src="%simages/calbutton.gif" alt="calendar" id="%s_btn"  />
<script type="text/javascript">
    Calendar.setup({
        inputField     :    "%s",
        ifFormat       :    "%s",
        button         :    "%s_btn",
        singleClick    :    true,
        showsTime      :    true
    });
</script>"""



class DateTimeWidget(forms.widgets.TextInput):
    input_type = "datetime"
    dformat = '%Y-%m-%d %H:%M'
    def render(self, name, value, attrs=None):
        if value is None: value = ''
        final_attrs = self.build_attrs(attrs, type=self.input_type, name=name)
        if value != '': 
            try:
                final_attrs['value'] = \
                                   force_unicode(value.strftime(self.dformat))
            except:
                final_attrs['value'] = \
                                   force_unicode(value)
        if not final_attrs.has_key('id'):
            final_attrs['id'] = u'%s_id' % (name)
        id = final_attrs['id']
        
        jsdformat = self.dformat #.replace('%', '%%')
        cal = calbtn % (settings.MEDIA_URL, id, id, jsdformat, id)
        a = u'<input%s />%s' % (forms.util.flatatt(final_attrs), cal)
        return mark_safe(a)

    def value_from_datadict(self, data, files, name):
        dtf = formats.get_format('DATETIME_FORMAT')
        empty_values = forms.fields.EMPTY_VALUES

        value = data.get(name, None)
        if value in empty_values:
            return None
        if isinstance(value, datetime.datetime):
            return value
        if isinstance(value, datetime.date):
            return datetime.datetime(value.year, value.month, value.day)
        for format in dtf:
            try:
                return datetime.datetime(*time.strptime(value, format)[:6])
            except ValueError:
                continue
        return None



class EnableDisable(forms.widgets.TextInput):
    input_type = "checkbox"
    checked=False

    def setChecked(self,checked):
        self.checked = checked
	
    def render(self, name, value, attrs=None):
        if value is None: value = ''
        final_attrs = self.build_attrs(attrs, type=self.input_type, name=name)
        if not final_attrs.has_key('id'):
            final_attrs['id'] = u'%s_id' % (name)
        id = final_attrs['id']
	#we need to pass checked so the feed appear checked 
	# need to figure this out yet
	if self.checked == True:
	    a = u'<input%s  checked = "checked" onClick=\'disableFields(this, whole )\'/>' % (forms.util.flatatt(final_attrs))
	else:
	    a = u'<input%s  onClick=\'disableFields(this, whole )\'/>' % (forms.util.flatatt(final_attrs))
        return mark_safe(a)

    def value_from_datadict(self, data, files, name):
        dtf = formats.get_format('DATETIME_FORMAT')
        empty_values = forms.fields.EMPTY_VALUES

        value = data.get(name, None)
        if value in empty_values:
            return None
        if isinstance(value, datetime.datetime):
            return value
        if isinstance(value, datetime.date):
            return datetime.datetime(value.year, value.month, value.day)
        for format in dtf:
            try:
                return datetime.datetime(*time.strptime(value, format)[:6])
            except ValueError:
                continue
        return None
