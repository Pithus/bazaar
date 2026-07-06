

def get_genom():
    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS, basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD))
    entire_genom = []
    query={"query": {"match_all": {}}}
    reports = es.search(index=settings.ELASTICSEARCH_APK_INDEX, body=query)

    for report in reports:
        report = report['_source']
        sha256 = report['sha256']
        genom = None
        threat = 'unknown'
        try:
            genom = report['andro_cfg']['genom']
            threat = report['vt_report']['attributes']['popular_threat_classification']['suggested_threat_label']
        except Exception as e:
            logging.error(f'Get Genom: {e}')
        if genom:
            entire_genom.append(f'{sha256}-{threat},{genom}')

    return entire_genom
