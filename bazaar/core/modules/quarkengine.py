import os
import shutil
from datetime import datetime, timedelta

from tempfile import NamedTemporaryFile
from tqdm import tqdm

from django.conf import settings
from django.core.files.storage import default_storage

from quark.core.quark import Quark
from quark.core.struct.ruleobject import RuleObject as QuarkRule
from quark import freshquark

from elasticsearch import Elasticsearch


es = Elasticsearch(
    settings.ELASTICSEARCH_HOSTS,
    basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD)
)


def run_freshquark():
    freshquark.download()
    src = os.path.join(freshquark.config.HOME_DIR, 'quark-rules/rules/')
    for file in os.listdir(src):
        shutil.copy(os.path.join(src, file), os.path.join('quark-rules/', file))


def analysis(sha256):
    es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'quark_analysis': 5}},
              retry_on_conflict=5)
    with NamedTemporaryFile() as f:
        f.write(default_storage.open(sha256).read())
        f.seek(0)
        data = Quark(f.name)

        rules_path = 'quark-rules'
        rules_list = os.listdir(rules_path)
        if datetime.now() - datetime.fromtimestamp(
            os.stat(os.path.join(rules_path, rules_list[0])).st_mtime
        ) >= timedelta(days=1):
            run_freshquark()
            rules_list = os.listdir(rules_path)

        for single_rule in tqdm(rules_list):
            if single_rule.endswith('json'):
                rule_path = os.path.join(rules_path, single_rule)
                rule_checker = QuarkRule(rule_path)
                try:
                    data.run(rule_checker)
                    data.generate_json_report(rule_checker)
                except Exception:
                    pass

        json_report = data.get_json_report()
        if json_report:
            es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'quark_analysis': 2}},
                      retry_on_conflict=5)
            es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': {'quark': json_report}},
                      retry_on_conflict=5)
        else:
            es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'quark_analysis': -1}},
                      retry_on_conflict=5)

    del json_report, rules_list, data
    return {'status': 'success', 'info': ''}
