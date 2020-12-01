from django.db import models


class FileUpload(models.Model):
    apk = models.FileField()

    class Meta:
        managed = False
