from django.conf import settings
from django.db import models
import uuid


class Yara(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=256, help_text='The fancy name of your Yara rule')
    content = models.TextField(help_text='Paste the content of your Yara rule')
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    last_update = models.DateTimeField()
    is_private = models.BooleanField(default=False)

    @staticmethod
    def get_es_index_names(user=None):
        public_es_index = 'yara_matches_public'
        private_es_index = None
        if user:
            private_es_index = f'yara_matches_private_{user.id}'
        return public_es_index, private_es_index

    def get_es_index_name(self):
        public_es_index, private_es_index = Yara.get_es_index_names(self.owner)
        if self.is_private:
            return private_es_index
        return public_es_index


# makemigrations --> génère le modèle de la DB
# migrate --> applique la modèle à la DB
