import binascii
import gc
import glob
import logging
import os
import re
import shutil
import time
import uuid
import zipfile
from datetime import datetime
from tempfile import NamedTemporaryFile, TemporaryDirectory

import dexofuzzy
import requests
import ssdeep
import vt
import yara
from androcfg.call_graph_extractor import CFG
from androguard.core.bytecodes.apk import APK
from androguard.misc import AnalyzeAPK
from apkid.apkid import Scanner, Options
from apkid.output import OutputFormatter
from apkid.rules import RulesManager
from django.conf import settings
from django.core.files import File
from django.core.files.storage import default_storage
from django.utils import timezone
from django_q.tasks import async_task
from elasticsearch import Elasticsearch
from google_play_scraper import app
from quark.Objects.quark import Quark
from quark.Objects.quarkrule import QuarkRule
from tqdm import tqdm

from bazaar.core.fingerprinting import ApplicationSignature
from bazaar.core.mobsf import MobSF
from bazaar.core.models import Yara
from bazaar.core.utils import strings_from_apk, upload_sample_to_malware_bazaar, insert_fuzzy_hash
from bazaar.front.utils import get_andro_cfg_storage_path

es = Elasticsearch(settings.ELASTICSEARCH_HOSTS, timeout=30, max_retries=5, retry_on_timeout=True)


def _prepare(sha256):
    tasks = {
        'apkid_analysis': 0,
        'ssdeep_analysis': 0,
        'extract_classes': 0,
        'quark_analysis': 0,
        'analysis_date': timezone.now()
    }

    if not es.exists(settings.ELASTICSEARCH_TASKS_INDEX, id=sha256):
        es.index(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body=tasks)
    else:
        es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': tasks}, retry_on_conflict=5)


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
        sign['main_activity'] = a.get_activities()
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

        if not es.exists(settings.ELASTICSEARCH_APK_INDEX, id=sha256):
            es.index(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body=sign)
        else:
            es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': sign}, retry_on_conflict=5)
    del a, sign, f
    gc.collect()

    return package


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
        return { 'status': 'error', 'info': ''}

    es_index = rule.get_es_index_name()

    try:
        es.indices.create(index=es_index, ignore=400)
    except Exception as e:
        pass

    try:
        yara_rule = yara.compile(source=rule.content)
    except Exception as e:
        logging.error(e)
        return { 'status': 'error', 'info': ''}

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
    if rule_id == -1:
        for rule in Yara.objects.all():
            execute_single_yara_rule(rule.id, sha256)
    else:
        # TODO: handle missing yara rule
        execute_single_yara_rule(rule_id, sha256)

    # TODO
    del rule
    gc.collect()

    return {'status': 'success', 'info': ''}


def retrohunt(rule_id):
    try:
        rule = Yara.objects.get(id=rule_id)
    except Exception as e:
        logging.exception(e)
        return

    _, hashes = default_storage.listdir('.')
    for h in hashes:
        execute_single_yara_rule(rule.id, h)

    del rule, hashes
    gc.collect()

    return {'status': 'success', 'info': ''}


def exodus_analysis(classes):
    start = time.time()
    exodus_url = 'https://reports.exodus-privacy.eu.org/api/trackers'
    r = requests.get(exodus_url)
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
    print(f'exodus_analysis took {stop - start}')
    return results


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
        print(f'AnalyzeAPK took {s2 - s1}')

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
        print(f'Cleanup took {s2 - s1}')

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
    print(f'extract_classes took {stop - start}')

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
                if b in BLOCK_TYPES.keys():
                    frosting_data['v2_signature_blocks'].append(
                        {
                            'value': str(hex(b)),
                            'comment': BLOCK_TYPES[b],
                            'content': binascii.b2a_base64(a._v2_blocks[b]).decode('utf-8').strip()
                        }
                    )
                else:
                    frosting_data['v2_signature_blocks'].append(
                        {
                            'value': str(hex(b)),
                            'comment': 'Unknown',
                            'content': binascii.b2a_base64(a._v2_blocks[b]).decode('utf-8').strip()
                        }
                    )
            es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={
                'doc': {'frosting_data': frosting_data}}, retry_on_conflict=5)
        except Exception as e:
            pass


def ssdeep_analysis(sha256):
    es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'ssdeep_analysis': 1}},
              retry_on_conflict=5)
    with NamedTemporaryFile() as f:
        f.write(default_storage.open(sha256).read())
        f.seek(0)

        ssdeep_apk = ''
        dexofuzzy_apk = ''
        try:
            ssdeep_apk = ssdeep.hash_from_file(f.name)
            insert_fuzzy_hash(ssdeep_apk, sha256, settings.ELASTICSEARCH_SSDEEP_APK_INDEX)
            dexofuzzy_apk = dexofuzzy.hash_from_file(f.name)
            insert_fuzzy_hash(dexofuzzy_apk, sha256, settings.ELASTICSEARCH_DEXOFUZZY_APK_INDEX)
        except Exception:
            pass

        doc = {
            'ssdeep': {
                'apk': ssdeep_apk,
                'manifest': '',
                'resources': '',
                'dex': []
            },
            'dexofuzzy': {
                'apk': dexofuzzy_apk,
                'dex': []
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
                        logging.error('Can not extract member: %s due to error %s', member, e)

            logging.info('Extracted %s .dex files', len(dex_files))

            apk.extract('AndroidManifest.xml')
            apk.extract('resources.arsc')

            try:
                doc['ssdeep']['manifest'] = ssdeep.hash_from_file(f'{tmp_dir}/AndroidManifest.xml')
                doc['ssdeep']['resources'] = ssdeep.hash_from_file(f'{tmp_dir}/resources.arsc')
            except Exception:
                pass

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

        es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': doc}, retry_on_conflict=5)

    del apk, f, doc
    gc.collect()

    es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'ssdeep_analysis': 2}},
              retry_on_conflict=5)

    return {'status': 'success', 'info': ''}


def _dict_to_list(d):
    ret = []
    for k, v in d.items():
        v['_name'] = k
        ret.append(v)
    return ret


def mobsf_analysis(sha256):
    es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'mobsf_analysis': 1}},
              retry_on_conflict=5)
    server = 'http://mobsf:8000'
    token = '515d3578262a2539cd13b5b9946fe17e350c321b91faeb1ee56095430242a4a9'
    mobsf = MobSF(token, server)

    try:
        with NamedTemporaryFile() as f:
            f.write(default_storage.open(sha256).read())
            f.seek(0)
            response = mobsf.upload(f'{sha256}.apk', f)
            to_store = None
            if response:
                mobsf.scan(response)
                report = mobsf.report_json(response)
                mobsf.delete_scan(response)

                to_store = {
                    'analysis_date': report['timestamp'],
                    'average_cvss': report['average_cvss'],
                    'security_score': report['security_score'],
                    'size': report['size'],
                    'md5': report['md5'],
                    'sha1': report['sha1'],
                    'icon_hidden': report['icon_hidden'],
                    'icon_found': report['icon_found'],
                    'manifest_analysis': report['manifest_analysis'],
                    'network_security': report['network_security'],
                    'file_analysis': report['file_analysis'],
                    # 'binary_analysis': report['binary_analysis'],
                    'url_analysis': report['urls'],
                    'email_analysis': report['emails'],
                    'secrets': report['secrets'],
                    'firebase_urls': report['firebase_urls'],
                    'playstore_details': report['playstore_details'],
                    'browsable_activities': _dict_to_list(report['browsable_activities']),
                    'detailed_permissions': _dict_to_list(report['permissions']),
                    'android_api_analysis': _dict_to_list(report['android_api']),
                    'code_analysis': _dict_to_list(report['code_analysis']),
                    'niap_analysis': _dict_to_list(report['niap_analysis']),
                    'domains_analysis': _dict_to_list(report['domains']),
                }

                es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': to_store},
                          retry_on_conflict=5)

        es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'mobsf_analysis': 2}},
                  retry_on_conflict=5)
    except Exception:
        es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'mobsf_analysis': -1}},
                  retry_on_conflict=5)

    del mobsf, response, to_store
    gc.collect()

    return {'status': 'success', 'info': ''}


def apkid_analysis(sha256):
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


def quark_analysis(sha256):
    es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'quark_analysis': 1}},
              retry_on_conflict=5)
    with NamedTemporaryFile() as f:
        f.write(default_storage.open(sha256).read())
        f.seek(0)
        data = Quark(f.name)

        rules_path = 'quark-rules'
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


def malware_bazaar_analysis(sha256):
    es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'malware_bazaar_analysis': 1}},
              retry_on_conflict=5)
    url = 'https://mb-api.abuse.ch/api/v1/'
    data_query = {
        'query': 'get_info',
        'hash': sha256
    }
    try:
        response = requests.post(url, data=data_query)
        if response.status_code != 200:
            upload_sample_to_malware_bazaar(sha256)

            es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256,
                      body={'doc': {'malware_bazaar_analysis': -1}}, retry_on_conflict=5)
            return
        json_response = response.json()
    except Exception as e:
        es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'malware_bazaar_analysis': -1}},
                  retry_on_conflict=5)
        return

    if 'data' in json_response:
        for d in json_response['data']:
            if d['sha256_hash'] == sha256:
                es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': {'malware_bazaar': d}},
                          retry_on_conflict=5)
                es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256,
                          body={'doc': {'malware_bazaar_analysis': 2}}, retry_on_conflict=5)
                return

    es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'malware_bazaar_analysis': -1}},
              retry_on_conflict=5)
    return


def andro_cfg(sha256, force=False):
    if default_storage.size(sha256) > 3*10485760:
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
                cfg = CFG(f.name, output_dir)
                cfg.compute_rules()
                report = cfg.generate_json_report()
                es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': {'andro_cfg': report}},
                          retry_on_conflict=5)
                output_path = get_andro_cfg_storage_path(sha256)
                files_to_upload = glob.glob(f'{output_dir}/**/*.bmp', recursive=True)
                files_to_upload.extend(glob.glob(f'{output_dir}/**/*.png', recursive=True))
                for img in files_to_upload:
                    img_path = img.replace(output_dir, '')
                    print(f'{output_path}{img_path}')
                    default_storage.save(f'{output_path}{img_path}', File(open(img, mode='rb')))
            except Exception as e:
                logging.error(e)


def vt_analysis(sha256):
    try:
        es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'vt_analysis': 1}},
                  retry_on_conflict=5)
        client = vt.Client(settings.VT_API_KEY)
        file = client.get_json(f'/files/{sha256}')['data']
        if file['attributes']['last_analysis_stats']:
            d = file['attributes']['last_analysis_stats']
            total = d['undetected'] + d['malicious']
            d['total'] = total
            # es.index(index=settings.ELASTICSEARCH_VT_INDEX, id=sha256, body=file)
            es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': {'vt': d, 'vt_report': file}},
                      retry_on_conflict=5)
        es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'vt_analysis': 2}},
                  retry_on_conflict=5)
    except Exception:
        es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'vt_analysis': -1}},
                  retry_on_conflict=5)
        return


def analyze(sha256, force=False):
    if not default_storage.exists(sha256):
        reason = f'{sha256} not found, unable to analyze'
        logging.error(reason)
        return {'status': 'error', 'info': reason}

    if es.exists(settings.ELASTICSEARCH_APK_INDEX, id=sha256) and not force:
        return {'status': 'success', 'info': ''}

    # Schedule all other tasks
    package = extract_attributes(sha256)
    if package:
        _prepare(sha256)
        async_task(mobsf_analysis, sha256)
        async_task(malware_bazaar_analysis, sha256)
        async_task(vt_analysis, sha256)
        async_task(apkid_analysis, sha256)
        async_task(ssdeep_analysis, sha256)
        async_task(frosting_analysis, sha256)
        async_task(extract_classes, sha256)
        async_task(quark_analysis, sha256)
        async_task(get_google_play_info, package)
        async_task(yara_analysis, sha256)
        async_task(andro_cfg, sha256)

    gc.collect()

    return {'status': 'success', 'info': ''}
