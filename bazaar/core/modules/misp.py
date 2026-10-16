import pymisp
import time
import logging
import gc
from django.conf import settings

from elasticsearch import Elasticsearch
from bazaar.core.services import ReportService


es = Elasticsearch(
    settings.ELASTICSEARCH_HOSTS,
    basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD)
)


def analysis(sha256):

    if settings.MISP_URL is None or settings.MISP_KEY is None:
        es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'misp_analysis': -1}},
                  retry_on_conflict=5)
        return {'status': 'success', 'info': 'MISP not setup'}

    # wait for mobsf to finish its analysis
    while es.get(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256)['_source']['mobsf_analysis'] == 1:
        time.sleep(10)

    try:
        misp = pymisp.PyMISP(settings.MISP_URL, settings.MISP_KEY, debug=False)
        matches = {}

        report = ReportService.get_report(sha256)
        iocs = [
            report.get("handle"),
            report.get("apk_hash"),
            report.get("sha1"),
            report.get("md5")
        ]
        for cert in report.get("certificates", []):
            iocs.append(cert.get("fingerprint_md5"))
            iocs.append(cert.get("fingerprint_sha1"))
            iocs.append(cert.get("fingerprint_sha256"))

        for ioc in iocs:

            results = misp.search(
                controller='attributes',
                value=ioc,
                include_context=True,
                include_event_uuid=True,
            )

            attributes = results.get('Attribute', [])

            for attribute in attributes:
                event_id = attribute.get("event_id")
                if not event_id:
                    continue
                event = attribute.get("Event", {})
                key = f"{ioc}:{event_id}"

                matches[key] = {
                    "ioc": ioc,
                    "event_id": str(event_id),
                    "event_info": event.get("info"),
                    "event_url": f"{settings.MISP_URL.rstrip('/')}/events/view/{str(event_id)}"
                }

        es.update(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256, body={'doc': {'misp_matches': matches}},
                  retry_on_conflict=5)

    except Exception as e:
        logging.exception(e)
        es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'misp_analysis': -1}},
                  retry_on_conflict=5)

    es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'misp_analysis': 2}},
              retry_on_conflict=5)

    del misp, report, iocs, matches
    gc.collect()

    return {'status': 'success', 'info': ''}
