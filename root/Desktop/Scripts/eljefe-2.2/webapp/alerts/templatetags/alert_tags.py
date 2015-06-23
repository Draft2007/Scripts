from django import template
register = template.Library()

@register.filter
def get(obj, field, default = ''):
  """
  Usage: 

  view: 
  some_dict = {'keyA':'valueA','keyB':{'subKeyA':'subValueA','subKeyB':'subKeyB'},'keyC':'valueC'}
  keys = ['keyA','keyC']
  template: 
  {{ some_dict|get:"keyA" }}
  {{ some_dict|get:"keyB"|get:"subKeyA" }}
  {% for key in keys %}{{ some_dict|get:key }}{% endfor %}
  """
  print obj
  try:
    return getattr(obj, field)
  except:
    return default