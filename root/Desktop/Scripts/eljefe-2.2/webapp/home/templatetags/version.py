from django import template

register = template.Library()


ELJEFE_VERSION_MAJOR=2
ELJEFE_VERSION_MINOR=2
ELJEFE_VERSION_PATCH=0


# Internal
SVN_REV_KEY= "$Rev$"

@register.assignment_tag()
def get_version():
    return str(ELJEFE_VERSION_MAJOR) + "." + str(ELJEFE_VERSION_MINOR) + "." + str(ELJEFE_VERSION_PATCH) 

def get_revision():
    
    global ELJEFE_VERSION_PATCH
    
    if not ELJEFE_VERSION_PATCH:
        input = open( "../revision", "r")
        data = input.read()
        
        rev=0
        for s in data.split(): 
            if s.isdigit():
                rev = s
        
        input.close()
         
        if not rev:
            hi_patch = open ("version_patch","r")
            rev = hi_patch.read()
            ELJEFE_VERSION_PATCH=int(rev)
            hi_patch.close()
        else:
            input = open("../revision","w")
            input.write(SVN_REV_KEY)
            input.close()
            
            input = open("version_patch","w")
            input.write(rev)
            input.close()

            ELJEFE_VERSION_PATCH=rev
    
    return str(ELJEFE_VERSION_PATCH)
