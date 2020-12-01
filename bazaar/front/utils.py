def transform_results(results):
    return [doc['_source'] for doc in results['hits']['hits']]
