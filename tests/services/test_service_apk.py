import pytest
from io import BytesIO
from unittest.mock import Mock, patch

from ..conftest import sha256, uuid

from bazaar.core.services import ApkService

def test_list_apk():
    assert ApkService.list_apk() == []

@patch("bazaar.core.services.apk.analyze")
@patch("bazaar.core.services.apk.default_storage.save")
@patch("bazaar.core.services.apk.default_storage.exists")
@patch("bazaar.core.services.apk.is_android")
def test_upload_apk(mock_is_android, mock_exists, mock_save, mock_analyze, fake_apk):
    mock_is_android.return_value = 'APK'
    mock_exists.return_value = False
    mock_save.return_value = None
    mock_analyze.return_value = None
    assert ApkService.upload_apk(fake_apk) == sha256

@patch("bazaar.core.services.apk.requests.get")
@patch("bazaar.core.services.apk.upload_apk")
def test_upload_from_url(mock_upload, mock_get):
    mock_upload.return_value = sha256
    response_mock = Mock()
    response_mock.status_code = 200
    mock_get.return_value = response_mock
    assert ApkService.upload_from_url('https://this.is.a.fake.url') == sha256

@patch("bazaar.core.services.apk.default_storage.exists")
def test_sample_exists(mock_exists):
    mock_exists.return_value = True
    assert ApkService.sample_exists(sha256) == True

@patch("bazaar.core.services.apk.default_storage.open")
@patch("bazaar.core.services.apk.default_storage.exists")
def test_download_sample(mock_exists, mock_open):
    fake_sample = BytesIO(b"test")
    mock_exists.return_value = True
    mock_open.return_value = fake_sample
    assert ApkService.download_sample(sha256) == fake_sample

