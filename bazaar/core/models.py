from django.conf import settings
from django.db import models


# class Yara(models.Model):
#     title = models.CharField(max_length=256)
#     content = models.TextField()
#     owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
#     last_update = models.DateTimeField()
#

# makemigrations --> génère le modèle de la DB
# migrate --> applique la modèle à la DB
