from django.urls import path

from bazaar.core.api_view import APKFileUploadView

app_name = "core"
urlpatterns = [
    path("upload", view=APKFileUploadView.as_view(), name="upload-apk"),
]


