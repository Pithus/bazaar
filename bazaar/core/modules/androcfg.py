import glob
import logging
from tempfile import NamedTemporaryFile, TemporaryDirectory
from django.core.files import File

from androcfg.call_graph_extractor import CFG

from django.conf import settings
from django.core.files.storage import default_storage
from bazaar.front.utils import get_andro_cfg_storage_path

from elasticsearch import Elasticsearch


es = Elasticsearch(
    settings.ELASTICSEARCH_HOSTS,
    basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD)
)


def analysis(sha256, force=False):
    if default_storage.size(sha256) > 3 * 10485760:
        return
    try:
        result = es.get(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256)['_source']
        if result.get('andro_cfg') is not None and not force:
            return
    except Exception:
        return

    with NamedTemporaryFile() as f:

        f.write(default_storage.open(sha256).read())
        f.seek(0)
        with TemporaryDirectory() as output_dir:
            try:
                cfg = CFG(f.name, output_dir, 'raw')
                cfg.compute_rules()
                report = cfg.generate_json_report()

                rules = report['rules']

                updated_rules = []
                updated_report = {}
                for rule in rules:
                    res = []
                    for findings in rule['findings']:
                        dexofuzzy_hash = findings['dexofuzzy_hash']
                        chunk_size, chunk, double_chunk = dexofuzzy_hash.split(':')
                        chunk_size = int(chunk_size)
                        findings['chunk'] = chunk
                        findings['chunk_size'] = chunk_size
                        findings['double_chunk'] = double_chunk
                        res.append(findings)

                    rule['findings'] = res
                    updated_rules.append(rule)

                updated_report['rules'] = updated_rules
                updated_report['genom'] = report['genom']
                es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256,
                          body={'doc': {'andro_cfg': updated_report}}, retry_on_conflict=5)

                output_path = get_andro_cfg_storage_path(sha256)
                files_to_upload = glob.glob(f'{output_dir}/**/*.bmp', recursive=True)
                files_to_upload.extend(glob.glob(f'{output_dir}/**/*.png', recursive=True))
                files_to_upload.extend(glob.glob(f'{output_dir}/**/*.raw', recursive=True))
                for img in files_to_upload:
                    img_path = img.replace(output_dir, '')
                    logging.info(f'{output_path}{img_path}')
                    default_storage.save(f'{output_path}{img_path}', File(open(img, mode='rb')))
            except Exception as e:
                logging.debug(f"ANDROCFG ERROR {e}")
