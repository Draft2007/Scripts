// ajax control to call /content
function CallWeb(url, id){

var requested  = false
if (window.XMLHttpRequest) {
requested = new XMLHttpRequest()
} else if (window.ActiveXObject){ // IE
try {
requested = new ActiveXObject("Msxml2.XMLHTTP")
} 
catch (e){
try{
requested = new ActiveXObject("Microsoft.XMLHTTP")
}
catch (e){}
}
}
else
return false
requested.onreadystatechange=function(){ 
loadpage(requested, id)
}
requested.open('GET', url, true) 
requested.send(null)
}


function loadpage(requested, id){
if (requested.readyState == 4 && (requested.status==200 || window.location.href.indexOf("http")==-1))
document.getElementById(id).innerHTML=requested.responseText
}


;(function($){
    $.fn.extend({
        donetyping: function(callback,timeout){
            timeout = timeout || 1e3; // 1 second default timeout
            var timeoutReference,
                doneTyping = function(el){
                    if (!timeoutReference) return;
                    timeoutReference = null;
                    callback.call(el);
                };
            return this.each(function(i,el){
                var $el = $(el);
                $el.is(':input') && $el.keypress(function(){
                    if (timeoutReference) clearTimeout(timeoutReference);
                    timeoutReference = setTimeout(function(){
                        doneTyping(el);
                    }, timeout);
                }).blur(function(){
                    doneTyping(el);
                });
            });
        }
    });
})(jQuery);
