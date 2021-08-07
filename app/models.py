from django.db import models
class Image(models.Model):
    title = models.CharField(max_length=255)
    image = models.FileField(upload_to='static/img/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title
