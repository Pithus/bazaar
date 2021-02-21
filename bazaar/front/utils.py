import dexofuzzy

from django.conf import settings
from elasticsearch import Elasticsearch


def transform_results(results):
    return [doc['_source'] for doc in results['hits']['hits']]


def transform_hl_results(results):
    ret = []
    for doc in results['hits']['hits']:
        d = {}
        for k, v in doc.items():
            if k.startswith('_'):
                k = k[1:]
            d[k] = v
        ret.append(d)
    return ret


def append_dexofuzzy_similarity(results, key, top_n=5):
    """
    Add dexofuzzy similarity info into a transformed result dict
    :param results: transformed result dict
    :param key: the key to append
    :param top_n: add only the n most similar results
    :return: the modified results dict
    """
    if len(results) > 50:
        return results

    for r in results:
        matches = []
        for sample in results:
            try:
                if r['source']['sha256'] != sample['source']['sha256']:
                    sim = dexofuzzy.compare(r['source']['dexofuzzy']['apk'], sample['source']['dexofuzzy']['apk'])
                    if sim > 0:
                        matches.append(
                            {'score': sim, 'sha256': sample['source']['sha256'], 'handle': sample['source']['handle']})
            except Exception as e:
                pass

        matches = sorted(matches, key=lambda ele: ele['score'], reverse=True)
        limit = min(len(matches), top_n)
        r[key] = matches[:limit]

    return results


def get_similarity_matrix(results):
    matrix = []
    for r in results:
        for s in r['sim']:
            matrix.append({
                'a': r['source']['sha256'],
                'b': s['sha256'],
                'score': s['score'],
            })

    return matrix


def get_aggregations(results):
    aggregations = {}
    result_count = results['hits']['total']['value']
    mapping = {
        'permissions': 'Requested permissions',
        'domains': 'Found domains',
        'android_api': 'Called Android API',
        'android_features': 'Requested Android features',
    }

    for k, v in results['aggregations'].items():
        for b in v['buckets']:
            b['doc_count'] = 100. * (b['doc_count'] / result_count)
        aggregations[k] = {
            'key': k,
            'title': mapping[k],
            'buckets': v['buckets']
        }

    return aggregations


def compute_status(status):
    success = True
    error = False
    running = len(status.keys()) != 8
    for k, v in status.items():
        if k != 'analysis_date':
            success = success and v == 2
            error = error or v == -1
            running = running or v == 1 or v == 0

    return {
        'in_error': error,
        'success': success,
        'running': running
    }


def generate_world_map(domains):
    import pygal
    from pygal.style import Style

    countries = {}
    for d in domains:
        try:
            if d['geolocation']['country_short']:
                c = d['geolocation']['country_short'].lower()
                if c in countries:
                    countries[c] +=1
                else:
                    countries[c] = 1
        except:
            pass
    custom_style = Style(
        foreground='#a991d4',
        foreground_strong='#a991d4',
        foreground_subtle='#a991d4',
        opacity='.6',
        opacity_hover='.9',
        transition='400ms ease-in',
        colors=('#6349b7', '#a991d4', '#E95355', '#E87653', '#E89B53'))
    worldmap_chart = pygal.maps.world.World(style=custom_style, margin=0, width=1200, height=600)
    worldmap_chart.add('Server locations', countries)
    worldmap_chart.show_legend = False
    if countries:
        return worldmap_chart.render(is_unicode=True)
    else:
        return None
