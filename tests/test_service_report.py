import pytest
from unittest.mock import patch

from .conftest import sha256, uuid

from bazaar.core.services.report import ReportService

@patch("bazaar.core.services.report.Elasticsearch.search")
def test_list_reports(mock_search, report_list):
    mock_search.return_value = {"hits": {"hits": [{"_source": report_list[0]}]}}
    assert ReportService.list_reports() == [report_list[0]]

@patch("bazaar.core.services.report.Elasticsearch.get")
def test_get_report(mock_get, report_data):
    mock_get.return_value = {"_source": report_data}
    assert ReportService.get_report(sha256) == report_data

@patch("bazaar.core.services.report.Elasticsearch.get")
def test_get_detailed_status(mock_get, detailed_status):
    mock_get.return_value = {"_source": detailed_status}
    assert ReportService.get_detailed_status(sha256) == detailed_status

@patch("bazaar.core.services.report.Elasticsearch.get")
def test_get_status(mock_get, report_status, detailed_status):
    mock_get.return_value = {"_source": detailed_status}
    assert ReportService.get_status(sha256) == report_status
