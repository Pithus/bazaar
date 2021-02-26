from django.contrib import admin
from .models import Yara


@admin.register(Yara)
class YaraAdmin(admin.ModelAdmin):
    pass
