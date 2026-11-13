
from django import template

register = template.Library()

@register.filter(name='items')
def get_items(dictionary, key):
    if isinstance(dictionary, dict):
        return dictionary.get(key, {}).items()
    return []