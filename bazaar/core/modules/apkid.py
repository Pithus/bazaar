import gc
from tempfile import NamedTemporaryFile

from apkid.apkid import Options, Scanner
from apkid.output import OutputFormatter
from apkid.rules import RulesManager

from django.conf import settings
from django.core.files.storage import default_storage

from elasticsearch import Elasticsearch


es = Elasticsearch(
    settings.ELASTICSEARCH_HOSTS,
    basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD)
)


def analysis(sha256):
    es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'apkid_analysis': 1}},
              retry_on_conflict=5)
    options = Options(
        timeout=30,
        verbose=False,
        entry_max_scan_size=settings.DATA_UPLOAD_MAX_MEMORY_SIZE,
        recursive=True,
    )
    output = OutputFormatter(
        json_output=True,
        output_dir=None,
        rules_manager=RulesManager(),
        include_types=False,
    )
    rules = options.rules_manager.load()
    scanner = Scanner(rules, options)

    with NamedTemporaryFile() as f:
        f.write(default_storage.open(sha256).read())
        f.seek(0)
        res = scanner.scan_file(f.name)

    try:
        findings = output.build_json_output(res)['files']
        es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': {'apkid': findings}},
                  retry_on_conflict=5)
        es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'apkid_analysis': 2}},
                  retry_on_conflict=5)
    except AttributeError:
        findings = {}
        es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': {'apkid': findings}},
                  retry_on_conflict=5)
        es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'apkid_analysis': -1}},
                  retry_on_conflict=5)

    del findings, rules, scanner, output, options, res
    gc.collect()

    return {'status': 'success', 'info': ''}
