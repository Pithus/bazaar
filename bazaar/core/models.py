import uuid

import yara
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.expressions import F
from elasticsearch import Elasticsearch


class Bookmark(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sample = models.CharField(max_length=256)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)


def check_yara_rule(rule):
    try:
        yara.compile(source=rule)
    except Exception as e:
        raise ValidationError(
            'Your rule does not compile.',
            params={'content': e},
        )


class Yara(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=256, help_text='The fancy name of your Yara rule')
    content = models.TextField(validators=[check_yara_rule], help_text='Paste the content of your Yara rule')
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

    @staticmethod
    def find_public_hunting_matches(sha256):
        es = Elasticsearch(settings.ELASTICSEARCH_HOSTS)
        public_index, _ = Yara.get_es_index_names()
        q = {
            'query': {
                'terms': {
                    'matches.apk_id': [sha256]
                }
            },
            'size': 5000
        }
        public_matches = []
        try:
            matches = es.search(index=public_index, body=q)['hits']['hits']
            for m in matches:
                public_matches.append(m.get('_source'))
        except Exception:
            pass
        return public_matches
