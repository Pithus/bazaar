import hashlib
import json
import re
import logging

import dexofuzzy
from django.utils import timezone
from tempfile import NamedTemporaryFile, TemporaryDirectory
import ssdeep
import requests
from androguard.core import apk
from django.conf import settings
from django.core.files.storage import default_storage
from django.urls import reverse
from django.utils.html import escape
from elasticsearch import Elasticsearch
import numpy
from scipy.cluster.hierarchy import dendrogram, linkage, to_tree
from scipy.spatial.distance import pdist
import pandas as pd
from http.client import responses as http_responses
from enum import Enum


def compute_status(status):
    success = True
    analysis_launched = False
    error = False
    running = len(status.keys()) != 8
    for k, v in status.items():
        if k != 'analysis_date':
            success = success and v == 2
            error = error or v == -1
            running = running or v == 1 or v == 0
            if v == 2:
                analysis_launched = True # if at least one step succeeded, the analysis was launched
    return {
        'in_error': error,
        'success': success,
        'analysis_launched': analysis_launched,
        'running': running
    }


def get_sha256_of_file_path(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()


def get_sha256_of_file(f):
    sha256_hash = hashlib.sha256()
    for byte_block in iter(lambda: f.read(4096), b""):
        sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def is_secret(inp):
    inp = inp.lower()
    """Check if captures string is a possible secret."""
    iden = (
        'api"', 'key"', 'api_"', 'secret"',
        'password"', 'aws', 'gcp', 's3',
        'token"', 'username"', 'user_name"', 'user"',
    )
    not_string = (
        'label_', 'text', 'hint', 'msg_', 'create_',
        'message', 'new', 'confirm', 'activity_',
        'forgot', 'dashboard_', 'current_', 'signup',
        'sign_in', 'signin', 'title_', 'welcome_',
        'change_', 'this_', 'the_', 'placeholder',
        'invalid_', 'btn_', 'action_', 'prompt_',
        'lable', 'hide_', 'old', 'update', 'error',
        'empty', 'txt_', 'lbl_',
    )
    not_str = any(i in inp for i in not_string)
    return any(i in inp for i in iden) and not not_str


def url_n_email_extract(dat, relative_path):
    """Extract URLs and Emails from Source Code."""
    urls = []
    emails = []
    urllist = []
    url_n_file = []
    email_n_file = []
    # URLs Extraction My Custom regex
    pattern = re.compile(
        (
            r'((?:https?://|s?ftps?://|'
            r'file://|javascript:|data:|www\d{0,3}[.])'
            r'[\w().=/;,#:@?&~*+!$%\'{}-]+)'
        ),
        re.UNICODE)
    urllist = re.findall(pattern, dat)
    uflag = 0
    for url in urllist:
        if url not in urls:
            urls.append(url)
            uflag = 1
    if uflag == 1:
        url_n_file.append(
            {'urls': urls, 'path': escape(relative_path)})

    # Email Extraction Regex
    regex = re.compile(r'[\w.-]{1,20}@[\w-]{1,20}\.[\w]{2,10}')
    eflag = 0
    for email in regex.findall(dat.lower()):
        if (email not in emails) and (not email.startswith('//')):
            emails.append(email)
            eflag = 1
    if eflag == 1:
        email_n_file.append(
            {'emails': emails, 'path': escape(relative_path)})
    return urllist, url_n_file, email_n_file


def strings_from_apk(apk_file):
    """Extract the strings from an app."""
    try:
        print('Extracting Strings from APK')
        dat = []
        secrets = []
        and_a = apk.APK(apk_file)
        rsrc = and_a.get_android_resources()
        pkg = rsrc.get_packages_names()[0]
        rsrc.get_strings_resources()
        for i in rsrc.values[pkg].keys():
            res_string = rsrc.values[pkg][i].get('string')
            if res_string:
                for duo in res_string:
                    cap_str = '"' + duo[0] + '" : "' + duo[1] + '"'
                    if is_secret(duo[0] + '"'):
                        secrets.append(cap_str)
                    dat.append(cap_str)
        data_string = ''.join(dat)
        urls, urls_nf, emails_nf = url_n_email_extract(
            data_string, 'Android String Resource')
        return {
            'urls_list': list(set(urls)),
            'url_nf': urls_nf,
            'emails_nf': emails_nf,
            'secrets': secrets,
        }
    except Exception:
        print('Extracting Strings from APK')
        return {}


class MalwareBazaarUploadStatus(Enum):
    SUCCESS = True
    FAILURE = False
    FAILURE_ALREADY_KNOWN = 'file_already_known'

def upload_sample_to_malware_bazaar(sha256):
    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS, basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD))
    try:
        result = es.get(index=settings.ELASTICSEARCH_APK_INDEX, id=sha256)['_source']
        if not result or 'vt' not in result:
            return

        if result['vt']['malicious'] > 1 and 'malware_bazaar' not in result:
            logging.info(f'Uploading {sha256} to Malware Bazaar')
            uri = reverse('front:report', args=[sha256])
            data = {
                'tags': [
                    'apk',
                ],
                'references': {
                    'links': [
                        f'https://beta.pithus.org{uri}',
                    ]
                }
            }
            headers = {'Auth-Key': settings.MALWARE_BAZAAR_API_KEY}

            with NamedTemporaryFile() as f:
                f.write(default_storage.open(sha256).read())
                f.seek(0)
                files = {
                    'json_data': (None, json.dumps(data), 'application/json'),
                    'file': (open(f.name, 'rb'))
                }
                response = requests.post('https://mb-api.abuse.ch/api/v1/', files=files, verify=True, headers=headers)
                if response.ok:
                    json_response = response.json()
                    if not 'query_status' in json_response:
                        logging.error(f"Unexpected result from Malware Bazaar API, no 'query_status' received.")
                        return MalwareBazaarUploadStatus.FAILURE

                    elif json_response['query_status'] == 'inserted':
                        logging.info(f"Upload to Malware Bazaar: Sample {sha256} marked as [inserted]. Check again later.")
                        return MalwareBazaarUploadStatus.SUCCESS

                    elif json_response['query_status'] == 'file_already_known':
                        logging.warn(f"Upload to Malware Bazaar failed because file is already known.")
                        # Upload failed because file is already known at MB, 
                        # but if we're it means we couldn't find a report
                        return MalwareBazaarUploadStatus.FAILURE_ALREADY_KNOWN
                    else:
                        logging.error(f"Failed to upload to Malware Bazaar: query_status: {json_response['query_status']}")
                        return MalwareBazaarUploadStatus.FAILURE

                else:
                    logging.error(f"Request to Malware Bazaar failed with error code: {response.status_code} {http_responses[response.status_code]}")
                    return MalwareBazaarUploadStatus.FAILURE
        else:
            logging.warn(f"Malware Bazaar: not uploading because a report for this file already exists, or the file is not flagged as malicious by VirusTotal")
    except Exception as e:
        logging.error(f'Malware Bazaar: {e}')
    return MalwareBazaarUploadStatus.FAILURE


def insert_fuzzy_hash(hash_value, sha256, index):
    chunksize, chunk, double_chunk = hash_value.split(':')
    chunksize = int(chunksize)

    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS, basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD))

    document = {'chunk_size': chunksize, 'chunk': chunk, 'double_chunk': double_chunk, 'sha256': sha256}

    es.index(index=index, id=sha256, body=document)
    es.indices.refresh(index=index)


def get_matching_items_by_ssdeep(ssdeep_value, threshold_grade, index, sha256):
    chunksize, chunk, double_chunk = ssdeep_value.split(':')
    chunksize = int(chunksize)

    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS, basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD))

    query = {
        'query': {
            'bool': {
                'must': [
                    {
                        'terms': {
                            'chunk_size': [chunksize, chunksize * 2, int(chunksize / 2)]
                        }
                    },
                    {
                        'bool': {
                            'should': [
                                {
                                    'match': {
                                        'chunk': {
                                            'query': chunk
                                        }
                                    }
                                },
                                {
                                    'match': {
                                        'double_chunk': {
                                            'query': double_chunk
                                        }
                                    }
                                }
                            ],
                            'minimum_should_match': 1
                        }
                    }
                ]
            }
        }
    }

    results = es.search(index=index, body=query)

    sha256_list_to_return = []

    for record in results['hits']['hits']:
        if record['_source']['sha256'] != sha256:
            chunk_size, chunk, double_chunk = record['_source']['chunk_size'], record['_source']['chunk'], record['_source']['double_chunk']
            record_ssdeep = f'{chunk_size}:{chunk}:{double_chunk}'
            ssdeep_grade = ssdeep.compare(record_ssdeep, ssdeep_value)

            if ssdeep_grade >= threshold_grade:
                sha256_list_to_return.append((record['_source']['sha256'], ssdeep_grade))

    return sha256_list_to_return


def get_matching_items_by_ssdeep_func(ssdeep_value, threshold_grade, index, sha256):
    chunksize, chunk, double_chunk = ssdeep_value.split(':')
    chunksize = int(chunksize)
    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS, basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD))
    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "terms": {
                            "andro_cfg.rules.findings.chunk_size": [chunksize, chunksize * 2, int(chunksize / 2)]
                        }
                    },
                    {
                        'bool': {
                            'should': [
                                {
                                    'match': {
                                        'andro_cfg.rules.findings.chunk': {
                                            'query': chunk
                                        }
                                    }
                                },
                                {
                                    'match': {
                                        'andro_cfg.rules.findings.double_chunk': {
                                            'query': double_chunk
                                        }
                                    }
                                }
                            ],
                            'minimum_should_match': 1
                        }
                    }
                ]
            }
        }
    }

    results = es.search(index=index, body=query)
    sha256_list_to_return = []

    for record in results['hits']['hits']:
        for rule in record['_source']['andro_cfg']['rules']:
            for f in rule['findings']:
                chunk_size, chunk, double_chunk = f['chunk_size'], f['chunk'], f['double_chunk']
                record_ssdeep = f'{chunk_size}:{chunk}:{double_chunk}'
                ssdeep_grade = ssdeep.compare(record_ssdeep, ssdeep_value)

                if ssdeep_grade >= threshold_grade:
                    sha256_list_to_return.append((record['_source']['sha256'], ssdeep_grade))

    return sha256_list_to_return


def get_matching_items_by_dexofuzzy(dexofuzzy_value, threshold_grade, index, sha256):
    chunksize, chunk, double_chunk = dexofuzzy_value.split(':')
    chunksize = int(chunksize)

    es = Elasticsearch(settings.ELASTICSEARCH_HOSTS, basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD))

    query = {
        'query': {
            'bool': {
                'must': [
                    {
                        'terms': {
                            'chunk_size': [chunksize, chunksize * 2, int(chunksize / 2)],
                        }
                    },
                    {
                        'bool': {
                            'should': [
                                {
                                    'match': {
                                        'chunk': {
                                            'query': chunk
                                        }
                                    }
                                },
                                {
                                    'match': {
                                        'double_chunk': {
                                            'query': double_chunk
                                        }
                                    }
                                }
                            ],
                            'minimum_should_match': 1
                        }
                    }
                ]
            }
        }
    }

    results = es.search(index=index, body=query)

    sha256_list_to_return = []

    for record in results['hits']['hits']:
        if record['_source']['sha256'] != sha256:
            chunk_size, chunk, double_chunk = record['_source']['chunk_size'], record['_source']['chunk'], record['_source']['double_chunk']
            record_dexofuzzy = f'{chunk_size}:{chunk}:{double_chunk}'
            dexofuzzy_grade = dexofuzzy.compare(record_dexofuzzy, dexofuzzy_value)

            if dexofuzzy_grade >= threshold_grade:
                sha256_list_to_return.append(
                    (record['_source']['sha256'], dexofuzzy_grade))

    return sha256_list_to_return


def compute_genetic_analysis(results):

    def normalize(data):
        d_prime = []
        for i in data:
            d_prime.append((100 * i) / max(data))
        return d_prime

    data = {}
    for r in results:
        r = r['source']
        try:
            app = (r['sha256'], r['handle'])
            genom = r['andro_cfg']['genom']
            data[app] = [int(x.strip()) for x in genom.split(',')]
        except Exception:
            pass # No genom found

    distances = pdist(list(data.values()))  # compute distance over all dimensions
    normalized_dist = normalize(distances)
    z = linkage(normalized_dist)
    x = dendrogram(z, orientation='top', no_labels=True, labels=list(data.keys()))

    # Add a few more data to help the JS
    x["max_x"] = numpy.amax(x["icoord"])
    x["max_y"] = numpy.amax(x["dcoord"])
    x["labels"] = list(data.keys())

    return x

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
