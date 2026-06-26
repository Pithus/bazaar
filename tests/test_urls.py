import pytest
from django.urls import resolve, reverse

sha256 = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
uuid = 'fa9c0834-7f94-474a-88d2-25e0f936d71c'
foo = 'this/is/a/test/path'

def test_home():
    assert reverse("front:home") == "/"
    assert resolve("/").view_name == "front:home"

@pytest.mark.django_db
def test_robots_txt(client):
    response = client.get("/robots.txt")

    assert response.status_code == 200
    assert response["Content-Type"] == "text/plain"
    assert "User-agent" in response.content.decode()

def test_report():
    assert reverse("front:report", kwargs={"sha256": sha256}) == f"/report/{sha256}"
    assert resolve(f"/report/{sha256}").view_name == "front:report"

def test_report_json():
    assert reverse("front:export_report", kwargs={"sha256": sha256}) == f"/report/{sha256}/json"
    assert resolve(f"/report/{sha256}/json").view_name == "front:export_report"

def test_report_card():
    assert reverse("front:og_card", kwargs={"sha256": sha256}) == f"/report/{sha256}/card"
    assert resolve(f"/report/{sha256}/card").view_name == "front:og_card"

def test_apk_upload():
    assert reverse("front:basic_upload") == "/apk/"
    assert resolve(f"/apk/").view_name == "front:basic_upload"

def test_apk_download():
    assert reverse("front:download_sample", kwargs={"sha256": sha256}) == f"/apk/{sha256}"
    assert resolve(f"/apk/{sha256}").view_name == "front:download_sample"

def test_url_download():
    assert reverse("front:basic_url_download") == "/url/"
    assert resolve("/url/").view_name == "front:basic_url_download"

def test_similarity_search():
    assert reverse("front:similarity_search") == "/similar/"
    assert resolve("/similar/").view_name == "front:similarity_search"

def test_similarity_search_sha256():
    assert reverse("front:similarity_search", kwargs={"sha256": sha256}) == f"/similar/{sha256}"
    assert resolve(f"/similar/{sha256}").view_name == "front:similarity_search"

def test_my_rules():
    assert reverse("front:my_rules") == "/rules/"
    assert resolve("/rules/").view_name == "front:my_rules"

def test_my_rule_create():
    assert reverse("front:my_rule_create") == "/rules/new"
    assert resolve(f"/rules/new").view_name == "front:my_rule_create"

def test_my_rule_edit():
    assert reverse("front:my_rule_edit", kwargs={"uuid": uuid}) == f"/rules/{uuid}/edit"
    assert resolve(f"/rules/{uuid}/edit").view_name == "front:my_rule_edit"

def test_my_rule_delete():
    assert reverse("front:my_rule_delete", kwargs={"uuid": uuid}) == f"/rules/{uuid}/delete"
    assert resolve(f"/rules/{uuid}/delete").view_name == "front:my_rule_delete"

def test_my_rule_retro():
    assert reverse("front:my_rule_retro", kwargs={"uuid": uuid}) == f"/rules/{uuid}/retro"
    assert resolve(f"/rules/{uuid}/retro").view_name == "front:my_rule_retro"

def test_get_genom():
    assert reverse("front:get_genom") == "/androcfg/all"
    assert resolve("/androcfg/all").view_name == "front:get_genom"

def test_get_andgrocfg_code():
    assert reverse("front:get_andgrocfg_code", kwargs={"sha256": sha256, "foo": foo})  == f"/androcfg/{sha256}/{foo}"
    assert resolve(f"/androcfg/{sha256}/{foo}").view_name == "front:get_andgrocfg_code"