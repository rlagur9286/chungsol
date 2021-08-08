from django.contrib import admin
from .models import Image
from django.conf import settings


class ImageAdmin(admin.ModelAdmin):

    def save_model(self, request, obj, form, change):
        if change:
            import os
            file_name = str(form.cleaned_data.get("image"))
            filePath = str(settings.BASE_DIR) + "/media/static/img/" + file_name
            if os.path.exists(filePath):
                os.remove(filePath)
        super().save_model(request, obj, form, change)

# Register your models here.
admin.site.register(Image, ImageAdmin)