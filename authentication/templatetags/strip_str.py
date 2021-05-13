# coding=utf-8
from django import template
from django.utils.safestring import mark_safe
register = template.Library()

@register.filter(name='strip_num')
def strip_num(num):
    i = str(num)
    return i.replace("-", "")
