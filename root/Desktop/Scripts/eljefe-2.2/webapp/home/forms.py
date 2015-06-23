from django import forms

class stationSearch(forms.Form):
    IP = forms.CharField(max_length=20,required=False,label="IP Address")
    hostname = forms.CharField(max_length=20,required=False,label="Hostname")
    
    def __init__(self, *args, **kwargs):
        super(stationSearch, self).__init__(*args, **kwargs)

class binariesSearch(forms.Form):
    binary_name = forms.CharField(max_length=20,required=False,label="Binary Name")
    binary_sha1 = forms.CharField(max_length=40,required=False,label="Binary SHA1")
    binary_sha256 = forms.CharField(max_length=64,required=False,label="Binary SHA256")
    binary_md5 = forms.CharField(max_length=32,required=False,label="Binary MD5")
    code_sha1 = forms.CharField(max_length=40,required=False,label="Code Section SHA1")
    
    def __init__(self, *args, **kwargs):
        super(binariesSearch, self).__init__(*args, **kwargs)

class eventsSearch(forms.Form):
    username = forms.CharField(max_length=20,required=False,label="Username")
    binary = forms.CharField(max_length=20,required=False,label="Binary Name")
    parent = forms.CharField(max_length=20,required=False,label="Parent Name")
    
    def __init__(self, *args, **kwargs):
        super(eventsSearch, self).__init__(*args, **kwargs)


INTRUSIONCHOICES=[
('PRIVILEGES: NON-SYSTEM to SYSTEM','PRIVILEGES: NON-SYSTEM to SYSTEM'),
('CALL CHAIN: iexplorer->java->cmd','CALL CHAIN: iexplorer->java->cmd'),
('EXECUTING PARENT: LSASS.exe','EXECUTING PARENT: LSASS.exe'),
('ENTROPY: SUSPICIOUS','ENTROPY: SUSPICIOUS'),
('FLAGS: SUSPICIOUS','FLAGS: SUSPICIOUS'),
]


class intrusionSearch(forms.Form):
    startdate = forms.DateTimeField(required=False,label="From")
    enddate = forms.DateTimeField(required=False,label="To",)
    method = forms.ChoiceField(label="Method",choices=INTRUSIONCHOICES)

        
class ClientSettingsForm(forms.Form):
    username = forms.CharField(max_length=64)
    password = forms.CharField(max_length=64)
    host = forms.GenericIPAddressField()
    port = forms.IntegerField(max_value=65535, min_value=0)
    
    
    
