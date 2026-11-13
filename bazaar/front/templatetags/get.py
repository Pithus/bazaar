from django import template

register = template.Library()


@register.filter(name='get')
def get(d, k):
    if not isinstance(d, dict):
        return []
    return d.get(k, [])
