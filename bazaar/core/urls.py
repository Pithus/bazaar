from bazaar.core.api_view import hello_world,apkupload
from django.urls import path

app_name = "core"
urlpatterns = [
    #path("upload", view=APKFileUploadView.as_view(), name="upload-apk"),
    path("hello",hello_world,name="upload-apk"),
    path("upload",apkupload,name="upload-apk")
]