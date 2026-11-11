import gc
import logging
import zipfile
from tempfile import NamedTemporaryFile, TemporaryDirectory

import dexofuzzy
import ssdeep

from django.conf import settings
from django.core.files.storage import default_storage
from bazaar.core.utils import insert_fuzzy_hash, insert_tlsh_hash, tlsh_hash_from_file

from elasticsearch import Elasticsearch


es = Elasticsearch(
    settings.ELASTICSEARCH_HOSTS,
    basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD)
)


def analysis(sha256):
    es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'ssdeep_analysis': 1}},
              retry_on_conflict=1)
    with NamedTemporaryFile() as f:
        f.write(default_storage.open(sha256).read())
        f.seek(0)

        ssdeep_apk = ''
        dexofuzzy_apk = ''
        tlsh_apk = ''
        try:
            tlsh_apk = tlsh_hash_from_file(f.name)
            insert_tlsh_hash(tlsh_apk, sha256, settings.ELASTICSEARCH_TLSH_APK_INDEX)
        except Exception as e:
            logging.exception(f'tlsh analysis: {e}')

        try:
            ssdeep_apk = ssdeep.hash_from_file(f.name)
            insert_fuzzy_hash(ssdeep_apk, sha256, settings.ELASTICSEARCH_SSDEEP_APK_INDEX)
            dexofuzzy_apk = dexofuzzy.hash_from_file(f.name)
            insert_fuzzy_hash(dexofuzzy_apk, sha256, settings.ELASTICSEARCH_DEXOFUZZY_APK_INDEX)
        except Exception as e:
            logging.exception(f'ssdeep analysis: {e}')

        doc = {
            'ssdeep': {
                'apk': ssdeep_apk,
                'manifest': '',
                'resources': '',
                'dex': []
            },
            'dexofuzzy': {
                'apk': dexofuzzy_apk,
                'dex': [],
            },
            'tlsh': {
                'apk': tlsh_apk,
                'dex': [],
            }
        }

        with TemporaryDirectory() as tmp_dir:
            apk = zipfile.ZipFile(f)

            file_list = apk.namelist()
            dex_files = []
            for member in file_list:
                if member.endswith('.dex'):
                    dex_files.append(member)
                    try:
                        apk.extract(member, tmp_dir)
                    except Exception as e:
                        logging.error('Can not extract member: %s due to an error %s', member, e)

            logging.info('Extracted %s .dex files', len(dex_files))

            try:
                apk.extract('AndroidManifest.xml', tmp_dir)
                doc['ssdeep']['manifest'] = ssdeep.hash_from_file(f'{tmp_dir}/AndroidManifest.xml')
            except Exception as e:
                logging.error(
                    'Can not extract "AndroidManifest.xml" due to an error %s', e)
            try:
                apk.extract('resources.arsc', tmp_dir)
                doc['ssdeep']['resources'] = ssdeep.hash_from_file(f'{tmp_dir}/resources.arsc')
            except Exception as e:
                logging.error(
                    'Can not extract "resources.arsc" due to an error %s', e)

            for file in dex_files:
                try:
                    doc['ssdeep']['dex'].append({
                        'file': file.replace(f'{tmp_dir}/', ''),
                        'hash': ssdeep.hash_from_file(f'{tmp_dir}/{file}')
                    })
                except Exception as e:
                    logging.error('Got an error %s', e)

                try:
                    doc['dexofuzzy']['dex'].append({
                        'file': file.replace(f'{tmp_dir}/', ''),
                        'hash': dexofuzzy.hash_from_file(f'{tmp_dir}/{file}')
                    })
                except Exception as e:
                    logging.error('Got an error %s', e)

                try:
                    doc['tlsh']['dex'].append({
                        'file': file.replace(f'{tmp_dir}/', ''),
                        'hash': tlsh_hash_from_file(f'{tmp_dir}/{file}')
                    })
                except Exception as e:
                    logging.error('Got an error %s', e)

        es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': doc}, retry_on_conflict=5)
        es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'ssdeep_analysis': 2}},
                  retry_on_conflict=5)

    del apk, f, doc
    gc.collect()

    return {'status': 'success', 'info': ''}
