from django import template
from django.utils.safestring import mark_safe

register = template.Library()


@register.filter(name='comma_to_br', is_safe=True)
def do(s):
    # Marking nosec because this is called  only on NIAP analysis returned data
    # DO NOT USE for other uncontrolled data.
    return mark_safe(s.replace(',', '<br>')) # nosec
