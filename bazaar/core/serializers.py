from rest_framework import serializers


class MessageResponseSerializer(serializers.Serializer):
    message = serializers.CharField()


class ErrorResponseSerializer(serializers.Serializer):
    message = serializers.CharField()


class InternalServerErrorSerializer(serializers.Serializer):
    status = serializers.CharField()


class HelloWorldResponseSerializer(serializers.Serializer):
    message = serializers.CharField()


class ReportListResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    reports = serializers.JSONField()


class ReportResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    report = serializers.JSONField()


class ReportStatusResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    report_status = serializers.JSONField()
    detailed_status = serializers.JSONField()


class ReportExistsResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    requested_hash = serializers.CharField()


class ExampleReportResponseSerializer(serializers.Serializer):
    status = serializers.CharField()
    report = serializers.JSONField()


class ApkUploadRequestSerializer(serializers.Serializer):
    apk = serializers.FileField(
        help_text="Android APK file to upload."
    )


class ApkUploadResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    file_hash = serializers.CharField(
        help_text="SHA256 hash of the uploaded APK."
    )


class SearchRequestSerializer(serializers.Serializer):
    q = serializers.CharField(
        help_text="Search query."
    )


class SearchResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    result = serializers.JSONField()


class ServiceStatusSerializer(serializers.Serializer):
    status = serializers.BooleanField()
    message = serializers.CharField()


class StatusDetailsSerializer(serializers.Serializer):
    db = ServiceStatusSerializer()
    elasticsearch = ServiceStatusSerializer()
    redis = ServiceStatusSerializer()

    django_q_workers = serializers.DictField(
        child=serializers.CharField(),
        help_text="Django Q worker statuses, indexed by cluster ID."
    )

    mobsf = ServiceStatusSerializer()
    malware_bazaar_api_connection = ServiceStatusSerializer()
    virustotal_api_connection = ServiceStatusSerializer()


class StatusResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    status = StatusDetailsSerializer()
