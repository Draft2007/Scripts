from django.db import models
from django.contrib import admin
    
class Action(models.Model):
    name = models.CharField(max_length=128)
    description = models.CharField(max_length=512)
    
    def __unicode__(self):
        return self.name    
    
class ExecutionFilter(models.Model):
    allow = models.BooleanField(verbose_name="Allowed",
                                help_text="""When true the filter will trigger when an executable not in executables is run.
    When false the filter will trigger when an executable in executables is run.""")
    
    executables = models.TextField(max_length=1024,
                                   help_text = """Executable names (comma separated).
    i.e iexplore.exe,svchosts.exe""")
    
    actions = models.ManyToManyField(Action)
    
    def filter(self, event):
        if self.allow:
            if event.binary.file_path not in self.executables.split(','):
                return True
        else:
            if event.binary.file_path in self.executables.split(','):
                return True
            
        return False
        
    def __unicode__(self):
        return "Execution Filter"
    
    
class TestFilter(models.Model):
    allow = models.BooleanField(verbose_name="Allowed")
    executables = models.TextField(max_length=1024)
    
    actions = models.ManyToManyField(Action)
    
    def filter(self, event):
        if self.allow:
            if event.binary.file_path not in self.executables.split(','):
                return True
        else:
            if event.binary.file_path in self.executables.split(','):
                return True
            
        return False
        
    def __unicode__(self):
        return "Other Filter"
    
admin.site.register(ExecutionFilter)