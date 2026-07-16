import logging
import requests
from tempfile import NamedTemporaryFile

from django.conf import settings
from django.core.files.storage import default_storage
from androguard.core.androconf import is_android

from elasticsearch import NotFoundError

from bazaar.core.utils import get_sha256_of_file
from bazaar.core.services import ReportService
from bazaar.core.tasks import analyze


class ApkException(Exception):
    pass


class URLException(Exception):
    pass


def list_apk():
    return []


def upload_apk(apk):

    if apk.size > settings.MAX_APK_UPLOAD_SIZE:
        raise ApkException("File too large")

    with NamedTemporaryFile() as tmp:
        for chunk in apk.chunks():
            tmp.write(chunk)
        tmp.seek(0)

        if is_android(tmp.name) != 'APK':
            raise ApkException("File is not an APK")

        sha256 = get_sha256_of_file(tmp)
        if default_storage.exists(sha256):
            try:
                if ReportService.get_status(sha256)["analysis_launched"] is False:
                    analyze(sha256, force=True)
            except NotFoundError:
                analyze(sha256)
            except Exception as e:
                logging.error(e)
                raise
        else:
            default_storage.save(sha256, tmp)
            analyze(sha256)

    return sha256


def upload_from_url(url):
    result = requests.get(url, stream=True, timeout=120)
    if result.status_code not in [200, 301, 302]:
        raise URLException("URL is not accessible.")
    try:
        sha256 = upload_apk(result.raw)
    except Exception:
        raise
    return sha256


def sample_exists(sha256):
    if default_storage.exists(sha256):
        return True
    return False


def download_sample(sha256):
    if sample_exists(sha256):
        return default_storage.open(sha256)
    else:
        return None
