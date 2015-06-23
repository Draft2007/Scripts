from django import forms
from django.forms import ModelForm
from alerts.models import *

class ExecutionFilterForm(ModelForm):
    class Meta:
        model = ExecutionFilter
        fields = ['allow', 'executables', 'actions']
    
class TestFilterForm(ModelForm):
    class Meta:
        model = TestFilter
        fields = ['allow', 'executables', 'actions']
        

class ImportForm(forms.Form):
    file = forms.FileField()