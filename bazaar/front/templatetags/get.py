from django import template

register = template.Library()


@register.filter(name='get')
def get(d, k):
    if not isinstance(d, dict):
        return None
    return d.get(k, None)
