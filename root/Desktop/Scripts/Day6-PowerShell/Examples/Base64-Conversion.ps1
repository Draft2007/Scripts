#####################################################################################################
#  A couple of functions for coverting to/from Base64 as defined in RFC4648, which clarifies RFC2045.
#  Both functions can accept piped input.
#####################################################################################################

function ConvertFrom-Base64 
{ 
    [CmdletBinding()] 
    Param( [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True)] $String )

    [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($String)) 

} 



function ConvertTo-Base64
{ 
    [CmdletBinding()] 
    Param( [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True)] $String )

    [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($String)) 
} 











#####################################################################################################
#  The same functions as above, but for Unicode instead of ASCII.
#####################################################################################################

function ConvertFromUNICODE-Base64 
{ 
    [CmdletBinding()] 
    Param( [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True)] $String )

    [System.Text.Encoding]::UNICODE.GetString([System.Convert]::FromBase64String($String)) 
} 


function ConvertToUNICODE-Base64
{ 
    [CmdletBinding()] 
    Param( [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True)] $String )

    [System.Convert]::ToBase64String([System.Text.Encoding]::UNICODE.GetBytes($String)) 
} 




