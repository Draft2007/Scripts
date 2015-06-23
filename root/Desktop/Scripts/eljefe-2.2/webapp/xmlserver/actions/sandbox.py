import ntpath
from lib.cuckoo.core.database import Database, TASK_PENDING
from ElJefeUtils import ActionTemplate
from home.models import *

class Action(ActionTemplate):
    NAME = "Sandbox"
    DESCRIPTION = "Sandbox Analysis Tool"

    def Act(self, event, flt):
        binary_id = event.binary.id
        binary = binaries.objects.get(id = binary_id)
        if not binary.data:
            # Check if it has already been added to the file download queue
            try:
                binary_requests.objects.get(id=binary.id)
            except:
                print 'creating'
                new_request = binary_requests()        
                new_request.binary = binary
                new_request.save()
                
            # Check if it has already been added to the file sandobx queue
            try:
                sandbox_queue.objects.get(id=binary.id)
            except:
                print 'creating sandboix'
                
                new_sandbox_req = sandbox_queue()
                new_sandbox_req.binary = binary
                new_sandbox_req.save()
                
        attempt_to_start_analysis(binary)
        
        for sandbox_queue_req in sandbox_queue.objects.all():
            attempt_to_start_analysis(sandbox_queue_req.binary)           
                            
def attempt_to_start_analysis(binary):
    print 'starting ana'
    db = Database()           
    tasks = db.list_tasks()
    
    filename = ntpath.basename(binary.file_path)
    output = ntpath.join('/tmp/', filename)                
    
    for task in tasks:
        if task.to_dict()['target'] == output:
            return
        else:
            with open(output, "wb") as handle:
                handle.write(binary.data)                        
                task_id = db.add_path(file_path=output,
                                      package="",
                                      timeout=120,
                                      options="",
                                      priority=1,
                                      machine="",
                                      custom="",
                                      memory=False,
                                      enforce_timeout=False,
                                      tags=None)
                if not task_id:
                    print 'asd'
                    err = "Failed adding sandbox analysis for %s" % filename                                
                    raise Exception(err)    