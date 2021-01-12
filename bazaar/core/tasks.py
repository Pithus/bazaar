import gc
import glob
import logging
import os
import re
import vt
import zipfile
from datetime import datetime
from tempfile import NamedTemporaryFile, TemporaryDirectory

import dexofuzzy
import requests
import ssdeep
from androguard.core.bytecodes.apk import APK
from androguard.misc import AnalyzeAPK
from apkid.apkid import Scanner, Options
from apkid.output import OutputFormatter
from apkid.rules import RulesManager
from django.conf import settings
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
from bazaar.core.utils import strings_from_apk

es = Elasticsearch([settings.ELASTICSEARCH_HOST])


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


def exodus_analysis(classes):
    exodus_url = "https://reports.exodus-privacy.eu.org/api/trackers"
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
        for c in classes:
            if t['compiled_code_signature'].search(c):
                results.append({
                    'id': t['id'],
                    'name': t['name'],
                    'code_signature': t['code_signature'],
                    'network_signature': t['network_signature'],
                    'website': t['website'],
                })
                break

    del tracker_signatures, r, classes, data
    gc.collect()

    return results


def extract_classes(sha256):
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
        a, d, dx = AnalyzeAPK(f.name)

        class_names = []
        try:
            for c in dx.get_classes():
                class_name = c.name
                if not class_name.startswith('Lkotlin/') and not class_name.startswith(
                    'Landroid/') and not class_name.startswith('Landroidx/') and not class_name.startswith(
                    'Ljavax/') and not class_name.startswith('Lkotlinx/') and not class_name.startswith(
                    'Ljava/') and _lcheck(class_name) and class_name not in class_names:
                    class_names.append(str(class_name))
        except Exception as e:
            es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'extract_classes': -1}},
                      retry_on_conflict=5)
            return {'status': 'failed', 'info': str(e)}

        doc = {
            'java_classes': ', '.join(class_names)
        }
        es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': doc}, retry_on_conflict=5)

        doc = {
            'trackers': exodus_analysis(class_names)
        }
        es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': doc}, retry_on_conflict=5)

    del a, d, dx, doc, f
    gc.collect()
    es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'extract_classes': 2}},
              retry_on_conflict=5)
    return {'status': 'success', 'info': ''}


def ssdeep_analysis(sha256):
    es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'ssdeep_analysis': 1}},
              retry_on_conflict=5)
    with NamedTemporaryFile() as f:
        f.write(default_storage.open(sha256).read())
        f.seek(0)

        doc = {
            'ssdeep': {
                'apk': ssdeep.hash_from_file(f.name),
                'manifest': '',
                'resources': '',
                'dex': []
            },
            'dexofuzzy': {
                'apk': dexofuzzy.hash_from_file(f.name),
                'dex': []
            }
        }

        with TemporaryDirectory() as tmp_dir:
            apk = zipfile.ZipFile(f)
            apk.extractall(tmp_dir)

            doc['ssdeep']['manifest'] = ssdeep.hash_from_file(f'{tmp_dir}/AndroidManifest.xml')
            doc['ssdeep']['resources'] = ssdeep.hash_from_file(f'{tmp_dir}/resources.arsc')

            for file in glob.glob(f'{tmp_dir}/*.dex'):
                try:
                    doc['ssdeep']['dex'].append({
                        'file': file.replace(f'{tmp_dir}/', ''),
                        'hash': ssdeep.hash_from_file(file)
                    })
                except Exception:
                    pass

                try:
                    doc['dexofuzzy']['dex'].append({
                        'file': file.replace(f'{tmp_dir}/', ''),
                        'hash': dexofuzzy.hash_from_file(file)
                    })
                except Exception:
                    pass

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
            if single_rule.endswith("json"):
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
    url = "https://mb-api.abuse.ch/api/v1/"
    data_query = {
        "query": "get_info",
        "hash": sha256
    }
    try:
        response = requests.post(url, data=data_query)
        if response.status_code != 200:
            es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256,
                      body={'doc': {'malware_bazaar_analysis': -1}}, retry_on_conflict=5)
            return
        json_response = response.json()
    except Exception:
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


def vt_analysis(sha256):
    try:
        es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'vt_analysis': 1}},
                  retry_on_conflict=5)
        client = vt.Client(settings.VT_API_KEY)
        file = client.get_object(f'/files/{sha256}')
        if file.last_analysis_stats:
            d = file.last_analysis_stats
            total = d['undetected'] + d['malicious']
            d['total'] = total
            es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': {'vt': d}},
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
        async_task(extract_classes, sha256)
        async_task(quark_analysis, sha256)
        async_task(get_google_play_info, package)

    gc.collect()

    return {'status': 'success', 'info': ''}
