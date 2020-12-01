import gc
import glob
import logging
import re
import requests
import zipfile
from tempfile import NamedTemporaryFile, TemporaryDirectory

import ssdeep
from androguard.core.bytecodes.apk import APK
from androguard.misc import AnalyzeAPK
from apkid.apkid import Scanner, Options
from apkid.output import OutputFormatter
from apkid.rules import RulesManager
from django.conf import settings
from django.core.files.storage import default_storage
from django_q.tasks import async_task
from elasticsearch import Elasticsearch
from google_play_scraper import app

from bazaar.core.fingerprinting import ApplicationSignature
from bazaar.core.mobsf import MobSF
from bazaar.core.utils import strings_from_apk

es = Elasticsearch([settings.ELASTICSEARCH_HOST])


def extract_attributes(sha256):
    with NamedTemporaryFile() as f:
        f.write(default_storage.open(sha256).read())
        f.seek(0)

        sign = ApplicationSignature.compute_from_apk(f.name)
        package = sign.handle
        sign = sign.to_dict()

        a = APK(f.name)
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
            # es.indices.refresh(index=settings.ELASTICSEARCH_APK_INDEX)
        else:
            es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': sign})
    del a, sign, f
    gc.collect()

    return package


def extract_ioc(sha256):
    with NamedTemporaryFile() as f:
        f.write(default_storage.open(sha256).read())
        f.seek(0)

        doc = strings_from_apk(f.name)

        es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': {'iocs': doc}})

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
    with NamedTemporaryFile() as f:
        f.write(default_storage.open(sha256).read())
        f.seek(0)
        a, d, dx = AnalyzeAPK(f.name)

        class_names = []
        for c in dx.get_classes():
            class_name = c.name
            if "$" not in class_name and class_name not in class_names:
                class_names.append(class_name)

        doc = {
            'external_classes': [c.name for c in dx.get_external_classes()],
            'trackers': exodus_analysis(class_names)
        }

        es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': doc})

    del a, d, dx, doc, f
    gc.collect()

    return {'status': 'success', 'info': ''}


def ssdeep_analysis(sha256):
    with NamedTemporaryFile() as f:
        f.write(default_storage.open(sha256).read())
        f.seek(0)

        doc = {
            'ssdeep': {
                'apk': ssdeep.hash_from_file(f.name),
                'manifest': '',
                'resources': '',
                'dex': []
            }
        }

        with TemporaryDirectory() as tmp_dir:
            apk = zipfile.ZipFile(f)
            apk.extractall(tmp_dir)

            doc['ssdeep']['manifest'] = ssdeep.hash_from_file(f'{tmp_dir}/AndroidManifest.xml')
            doc['ssdeep']['resources'] = ssdeep.hash_from_file(f'{tmp_dir}/resources.arsc')

            for file in glob.glob(f'{tmp_dir}/*.dex'):
                doc['ssdeep']['dex'].append({
                    'file': file.replace(f'{tmp_dir}/', ''),
                    'hash': ssdeep.hash_from_file(file)
                })

        es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': doc})

    del apk, f, doc
    gc.collect()

    return {'status': 'success', 'info': ''}


def _dict_to_list(d):
    ret = []
    for k, v in d.items():
        v['_name'] = k
        ret.append(v)
    return ret


def mobsf_analysis(sha256):
    server = 'http://mobsf:8000'
    token = '515d3578262a2539cd13b5b9946fe17e350c321b91faeb1ee56095430242a4a9'
    mobsf = MobSF(token, server)
    with NamedTemporaryFile() as f:
        f.write(default_storage.open(sha256).read())
        f.seek(0)
        response = mobsf.upload(f'{sha256}.apk', f)
        if response:
            mobsf.scan(response)
            report = mobsf.report_json(response)
            # mobsf.delete_scan(response)

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
                'binary_analysis': report['binary_analysis'],
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

            es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': to_store})

    del mobsf, response, to_store
    gc.collect()

    return {'status': 'success', 'info': ''}


def apkid_analysis(sha256):
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
    except AttributeError:
        findings = {}

    es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': {'apkid': findings}})

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
            return {'status': 'success', 'info': ''}
    except Exception as e:
        raise e
    finally:
        del details
        gc.collect()

    return {'status': 'error', 'info': f'Unable to retrieve Google Play details of {package}'}


def analyze(sha256):
    if not default_storage.exists(sha256):
        reason = f'{sha256} not found, unable to analyze'
        logging.error(reason)
        return {'status': 'error', 'info': reason}

    print('$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$')

    # Schedule all other tasks
    package = extract_attributes(sha256)
    if package:
        async_task(mobsf_analysis, sha256)
        async_task(apkid_analysis, sha256)
        async_task(ssdeep_analysis, sha256)
        async_task(extract_classes, sha256)
        async_task(get_google_play_info, package)

    gc.collect()

    return
