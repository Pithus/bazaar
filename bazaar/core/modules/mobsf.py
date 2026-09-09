import gc
import logging
from tempfile import NamedTemporaryFile

from django.conf import settings
from django.core.files.storage import default_storage
from bazaar.core.mobsf import MobSF


from tld import get_tld, is_tld

from elasticsearch import Elasticsearch


es = Elasticsearch(
    settings.ELASTICSEARCH_HOSTS,
    basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD)
)


def _check_tld(d):
    res = []
    for v in d:
        try:
            tld_try = get_tld(v['_name'], fix_protocol=True)

            if tld_try and is_tld(tld_try):
                res.append(v)
            else:
                continue
        except Exception:
            continue

    return res


def _dict_to_list(d):
    ret = []
    for k, v in d.items():
        v['_name'] = k
        ret.append(v)
    return ret


def _check_urls(d):
    res = []
    for i in d:
        for u in i['urls']:
            try:
                tld_try = get_tld(u)
                if tld_try and is_tld(tld_try):
                    res.append(i)
                else:
                    continue
            except Exception:
                continue

    return res


def analysis(sha256):

    es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'mobsf_analysis': 1}},
              retry_on_conflict=5)
    mobsf = MobSF(settings.MOBSF_SERVER, settings.MOBSF_TOKEN)

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

                updated_report_api = []
                for x in _dict_to_list(report['android_api']):
                    x['metadata']['id'] = x['_name']
                    updated_report_api.append(x)

                to_store = {
                    'analysis_date': report['timestamp'] if 'timestamp' in report else None,
                    'average_cvss': report['average_cvss'] if 'average_cvss' in report else None,
                    'size': report['size'] if 'size' in report else None,
                    'md5': report['md5'] if 'md5' in report else None,
                    'sha1': report['sha1'] if 'sha1' in report else None,
                    'icon_hidden': report['icon_hidden'] if 'icon_hidden' in report else None,
                    'icon_found': report['icon_found'] if 'icon_found' in report else None,
                    'manifest_analysis': report['manifest_analysis'] if 'manifest_analysis' in report else None,
                    'network_security': report['network_security'] if 'network_security' in report else None,
                    'file_analysis': report['file_analysis'] if 'file_analysis' in report else None,
                    'email_analysis': report['emails'] if 'emails' in report else None,
                    'secrets': report['secrets'] if 'secrets' in report else None,
                    'firebase_urls': report['firebase_urls'] if 'firebase_urls' in report else None,
                    'playstore_details': report['playstore_details'] if 'playstore_details' in report else None,
                    # 'security_score': report['appsec']['security_score'] ,
                    'url_analysis': _check_urls(report['urls']),
                    'browsable_activities': _dict_to_list(report['browsable_activities']),
                    'detailed_permissions': _dict_to_list(report['permissions']),
                    'android_api_analysis': updated_report_api,
                    'code_analysis': _dict_to_list(report['code_analysis']),
                    'niap_analysis': _dict_to_list(report['niap_analysis']),
                    'domains_analysis': _check_tld(_dict_to_list(report['domains'])),
                }

                es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': to_store},
                          retry_on_conflict=5)

        es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'mobsf_analysis': 2}},
                  retry_on_conflict=5)

    except Exception as e:
        logging.warning(e)
        es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'mobsf_analysis': -1}},
                  retry_on_conflict=5)

    try:
        del response, to_store
    except Exception:
        pass
    del mobsf
    gc.collect()

    return {'status': 'success', 'info': ''}
