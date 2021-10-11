from django import template
from django.utils.safestring import mark_safe

register = template.Library()


@register.filter(name='slash_to_tick', is_safe=True)
def do(s):
    return mark_safe(s.replace('/', '-'))
