import binascii
import gc
import logging
import time
import glob
import shutil
import uuid
import zipfile
import re
import dexofuzzy
import requests
import yara
from datetime import datetime
from tempfile import NamedTemporaryFile

from androguard.core.apk import APK
from androguard.misc import AnalyzeAPK
from google_play_scraper import app

from django.conf import settings
from django.core.files.storage import default_storage
from bazaar.core.fingerprinting import ApplicationSignature
from bazaar.core.utils import strings_from_apk

from elasticsearch import Elasticsearch


es = Elasticsearch(settings.ELASTICSEARCH_HOSTS, request_timeout=30, max_retries=5, retry_on_timeout=True, basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD))


def exodus_analysis(classes):
    start = time.time()
    exodus_url = 'https://reports.exodus-privacy.eu.org/api/trackers'
    r = requests.get(exodus_url, timeout=10)
    data = r.json()
    tracker_signatures = []
    for id, obj in data['trackers'].items():
        if len(obj['code_signature']) > 3:
            tracker_signatures.append({
                'id': obj['id'],
                'name': obj['name'],
                'code_signature': obj['code_signature'],
                'compiled_code_signature': re.compile(obj['code_signature']),
                'network_signature': obj['network_signature'],
                'website': obj['website'],
            })

    results = []

    for t in tracker_signatures:
        if t['compiled_code_signature'].search(classes):
            results.append({
                'id': t['id'],
                'name': t['name'],
                'code_signature': t['code_signature'],
                'network_signature': t['network_signature'],
                'website': t['website'],
            })
            continue

    del tracker_signatures, r, classes, data
    gc.collect()
    stop = time.time()
    logging.info(f'exodus_analysis took {stop - start}')
    return results


def extract_attributes(sha256):
    with NamedTemporaryFile() as f:
        f.write(default_storage.open(sha256).read())
        f.seek(0)

        sign = ApplicationSignature.compute_from_apk(f.name)
        package = sign.handle
        sign = sign.to_dict()
        a = APK(f.name)
        sign['uploaded_at'] = datetime.now()
        sign['sha256'] = sha256
        sign['activities'] = a.get_activities()
        sign['features'] = a.get_features()
        sign['libraries'] = a.get_libraries()
        sign['main_activity'] = a.get_main_activity()
        sign['min_sdk_version'] = a.get_min_sdk_version()
        sign['max_sdk_version'] = a.get_max_sdk_version()
        sign['target_sdk_version'] = a.get_target_sdk_version()
        sign['permissions'] = a.get_permissions()
        sign['aosp_permissions'] = a.get_requested_aosp_permissions()
        sign['third_party_permissions'] = a.get_requested_third_party_permissions()
        sign['providers'] = a.get_providers()
        sign['receivers'] = a.get_receivers()
        sign['services'] = a.get_services()
        sign['is_valid'] = a.is_valid_APK()
        sign['is_signed'] = a.is_signed()
        sign['is_signed_v1'] = a.is_signed_v1()
        sign['is_signed_v2'] = a.is_signed_v2()
        sign['is_signed_v3'] = a.is_signed_v3()

        if not es.exists(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256):
            es.index(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body=sign)
        else:
            es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': sign}, retry_on_conflict=5)
    del a, sign, f
    gc.collect()

    return package


def extract_classes(sha256):

    start = time.time()
    es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'extract_classes': 1}},
              retry_on_conflict=5)

    def _lcheck(name):
        name = str(name)
        count = name.count('/') + 1
        length = len(name)
        return length / count >= 2

    with NamedTemporaryFile() as f:
        f.write(default_storage.open(sha256).read())
        f.seek(0)
        s1 = time.time()
        a, d, dx = AnalyzeAPK(f.name)
        s2 = time.time()
        logging.debug(f'AnalyzeAPK took {s2 - s1}')

        # Extract classes
        s1 = time.time()
        class_names = []
        try:
            for class_name in dx.classes:
                if not class_name.startswith('Lkotlin/') and not class_name.startswith(
                    'Landroid/') and not class_name.startswith('Landroidx/') and not class_name.startswith(
                    'Ljavax/') and not class_name.startswith('Lkotlinx/') and not class_name.startswith(
                    'Ljava/'):  # and _lcheck(class_name) and class_name not in class_names:
                    class_names.append(str(class_name))
        except Exception as e:
            es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'extract_classes': -1}},
                      retry_on_conflict=5)
            return {'status': 'failed', 'info': str(e)}
        s2 = time.time()
        logging.debug(f'Cleanup took {s2 - s1}')

        java_classes = ' '.join(class_names)

        doc = {
            'java_classes': java_classes
        }
        es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': doc}, retry_on_conflict=5)

        doc = {
            'trackers': exodus_analysis(java_classes)
        }
        es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': doc}, retry_on_conflict=5)

    del a, d, dx, doc, f, java_classes, class_names
    gc.collect()
    es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'extract_classes': 2}},
              retry_on_conflict=5)

    stop = time.time()
    logging.info(f'extract_classes took {stop - start}')

    return {'status': 'success', 'info': ''}


def frosting_analysis(sha256):
    BLOCK_TYPES = {
        # 0x7109871a: 'SIGNv2',
        # 0xf05368c0: 'SIGNv3',
        0x2146444e: 'Google metadata',
        0x42726577: 'Verity padding',
        0x6dff800d: 'Source stamp V2 X509 cert',
        # JSON with some metadata, used by Chinese company Meituan
        0x71777777: 'Meituan metadata',
        # Dependencies metadata generated by Gradle and encrypted by Google Play.
        # '...The data is compressed, encrypted by a Google Play signing key...'
        # https://developer.android.com/studio/releases/gradle-plugin#dependency-metadata
        0x504b4453: 'Dependency metadata',
    }
    with NamedTemporaryFile() as f:
        f.write(default_storage.open(sha256).read())
        f.seek(0)

        try:
            a = APK(f.name)
            a.parse_v2_v3_signature()

            frosting_data = {
                'is_frosted': 0x2146444e in a._v2_blocks,
                'v2_signature_blocks': []
            }

            for b in a._v2_blocks:
                if b.id in BLOCK_TYPES.keys():
                    frosting_data['v2_signature_blocks'].append(
                        {
                            'value': str(hex(b.id)),
                            'comment': BLOCK_TYPES[b.id],
                            'content': binascii.b2a_base64(b.data).decode('utf-8').strip()
                        }
                    )
                else:
                    frosting_data['v2_signature_blocks'].append(
                        {
                            'value': str(hex(b.id)),
                            'comment': 'Unknown',
                            'content': binascii.b2a_base64(b.data).decode('utf-8').strip()
                        }
                    )
            es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={
                'doc': {'frosting_data': frosting_data}}, retry_on_conflict=5)
        except Exception as e:
            pass


def get_google_play_info(package):
    try:
        details = app(
            package,
            lang='en',  # defaults to 'en'
            country='us'  # defaults to 'us'
        )
        if details:
            es.index(index=settings.ELASTICSEARCH_GP_INDEX, id=package, body=details)
            del details
            return {'status': 'success', 'info': ''}
    except Exception:
        pass
    finally:
        gc.collect()

    return {'status': 'error', 'info': f'Unable to retrieve Google Play details of {package}'}


def extract_ioc(sha256):
    with NamedTemporaryFile() as f:
        f.write(default_storage.open(sha256).read())
        f.seek(0)

        doc = strings_from_apk(f.name)

        es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': {'iocs': doc}}, retry_on_conflict=5)

    del doc, f
    gc.collect()

    return {'status': 'success', 'info': ''}


def execute_single_yara_rule(rule_id, sha256):
    rule = Yara.objects.get(id=rule_id)

    if not default_storage.exists(sha256):
        reason = f'{sha256} not found, unable to analyze'
        logging.error(reason)
        return {'status': 'error', 'info': ''}

    es_index = rule.get_es_index_name()

    try:
        es.indices.create(index=es_index, ignore=400)
    except Exception as e:
        pass

    try:
        yara_rule = yara.compile(source=rule.content)
    except Exception as e:
        logging.error(e)
        return {'status': 'error', 'info': ''}

    document_uuid = uuid.uuid4()
    res_struct = {
        'name': rule.title,
        'rule': rule.id,
        'owner': rule.owner.id,
        'matching_date': timezone.now(),
        'matches': {
            'apk_id': sha256,
            'matching_files': [],
            'inner_rules': [],
        },
    }
    try:
        with NamedTemporaryFile() as f:
            f.write(default_storage.open(sha256).read())
            f.seek(0)
            with TemporaryDirectory() as tmp:
                shutil.copyfile(f.name, f'{tmp}/{sha256}.apk')
                with zipfile.ZipFile(f.name, 'r') as apk:
                    apk.extractall(tmp)

                for file in glob.iglob(f'{tmp}/**/*', recursive=True):
                    try:
                        found = yara_rule.match(file)
                        if len(found) > 0:
                            res_struct['matches']['matching_files'].append(file.replace(tmp, ''))
                            res_struct['matches']['inner_rules'].extend([str(f) for f in found])
                            logging.info(res_struct)
                    except Exception as e:
                        pass
    except Exception:
        return

    res_struct['matches']['inner_rules'] = list(set(res_struct['matches']['inner_rules']))

    q = {
        'query': {
            'bool': {
                'must': [
                    {'match': {'owner': rule.owner.id}},
                    {'match': {'rule': rule.id}},
                    {'match': {
                        'matches.apk_id': sha256}}
                ]
            }
        }
    }
    count_existing_matches = es.count(index=es_index, body=q)['count']
    if len(res_struct['matches']['matching_files']) > 0 and count_existing_matches == 0:
        try:
            es.index(index=es_index, id=document_uuid, body=res_struct)
            # TODO: notify user if match
        except Exception as e:
            logging.exception(e)

    del es_index, yara_rule, document_uuid, res_struct, f, tmp, file, found, q, count_existing_matches
    gc.collect()

    return {'status': 'success', 'info': ''}


def yara_analysis(sha256, rule_id=-1):
    rule = None
    if rule_id == -1:
        for rule in Yara.objects.all():
            execute_single_yara_rule(rule.id, sha256)
    else:
        execute_single_yara_rule(rule_id, sha256)

    del rule
    gc.collect()

    return {'status': 'success', 'info': ''}


def retrohunt(rule_id):
    rule = None
    try:
        rule = Yara.objects.get(id=rule_id)
    except Exception as e:
        logging.exception(e)
        return

    for report in scan(es, query={"query": {"match_all": {}}},
                       index=settings.ELASTICSEARCH_APK_INDEX,
                       ):
        _id = report.get('_source').get('sha256')
        execute_single_yara_rule(rule.id, _id)

    del rule
    gc.collect()

    return {'status': 'success', 'info': ''}