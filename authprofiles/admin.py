from django.contrib import admin

from .models import PassportAPI, PassportScope

# Register your models here.


class PassportAPIAdmin(admin.ModelAdmin):
    list_display = ("identifier", "name")


admin.site.register(PassportAPI, PassportAPIAdmin)
admin.site.register(PassportScope)
