from django.contrib import admin
from .models import Image


class ImageAdmin(admin.ModelAdmin):
    def save_model(self, request, obj, form, change):
        super(MyAdminView, self).save_model(request, obj, form, change)

# Register your models here.
admin.site.register(Image)
