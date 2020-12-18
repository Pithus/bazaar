import base64
import binascii
import hashlib
import logging
import zipfile
from hashlib import sha256, sha1
from io import BytesIO
from tempfile import NamedTemporaryFile

from PIL import Image
from androguard.core import androconf
from androguard.core.bytecodes.apk import APK

MAX_IMAGE_SIZE = 96, 96
androconf.show_logging(logging.ERROR)


class Certificate:
    """
    Helper class representing an X509 certificate
    """

    def __init__(self, cert):
        self.fingerprint = binascii.hexlify(cert.sha1).decode('ascii').lower()
        md5_digest = hashlib.md5(cert.dump()).digest()
        self.fingerprint_md5 = binascii.hexlify(md5_digest).decode('ascii').lower()
        self.fingerprint_sha1 = binascii.hexlify(cert.sha1).decode('ascii').lower()
        self.fingerprint_sha256 = binascii.hexlify(cert.sha256).decode('ascii').lower()
        self.issuer = cert.issuer.human_friendly
        self.subject = cert.subject.human_friendly
        self.serial = str(cert.serial_number)
        self.self_issued = cert.self_issued
        self.self_signed = cert.self_signed
        self.public_key_base64 = base64.b64encode(cert.public_key.contents).decode()
        self.not_before = cert.native['tbs_certificate']['validity']['not_before'].isoformat()
        self.not_after = cert.native['tbs_certificate']['validity']['not_after'].isoformat()

    def __str__(self):
        return 'Issuer: %s \n' \
               'Subject: %s \n' \
               'Fingerprint: %s \n' \
               'Serial: %s' % (self.issuer, self.subject, self.fingerprint, self.serial)


def get_sha256_of_file(file_path):
    """
    Returns the sha256sum of the given file
    :return: hex sha256sum
    """
    BLOCKSIZE = 65536
    hasher = sha256()
    with open(file_path, 'rb') as apk:
        buf = apk.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = apk.read(BLOCKSIZE)
    return str(hasher.hexdigest()).lower()


def get_check_sums_of_file(file_path):
    """
    Returns the check sums of the given file
    :return: list of tuple
    """
    BLOCKSIZE = 65536
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as apk:
        chunk = apk.read(BLOCKSIZE)
        while len(chunk) > 0:
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            chunk = apk.read(BLOCKSIZE)
    return [('md5', str(md5.hexdigest()).lower()),
            ('sha1', str(sha1.hexdigest()).lower()),
            ('sha256', str(sha256.hexdigest()).lower())]


def get_check_sums_of_file_as_dict(file_path):
    """
    Returns the check sums of the given file
    :return: list of tuple
    """
    BLOCKSIZE = 65536
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as apk:
        chunk = apk.read(BLOCKSIZE)
        while len(chunk) > 0:
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            chunk = apk.read(BLOCKSIZE)
    return {'md5': str(md5.hexdigest()).lower(),
            'sha1': str(sha1.hexdigest()).lower(),
            'sha256': str(sha256.hexdigest()).lower()}


def get_certificates(apk):
    """
    Returns the signing certificates of the given apk
    :param apk: apk `androguard.core.bytecodes.apk.APK` object
    :return: list of `scatter_scam_core.utils.Certificate`
    """
    certificates = []
    for c in apk.get_certificates():
        cert = Certificate(c)
        certificates.append(cert)
    return certificates


def compute_uaid(apk):
    """
    Computes the Universal Application ID of the given apk
    :param apk: apk `androguard.core.bytecodes.apk.APK` object
    :return: str
    """
    parts = [apk.get_package()]
    for c in get_certificates(apk):
        parts.append(c.fingerprint.upper())
    return sha1(' '.join(parts).encode('utf-8')).hexdigest().lower()


def icon_to_base64(apk_path, icon_path):
    """
    Extracts icon file located at `icon_path` in the APK file `apk_path`, scales it to 96x96px and returns its base64
    :param apk_path: location of the APK
    :param icon_path: location of the icon in the APK file
    :return: a base64 encoded icon, None if the icon is not an image but a `VectorDrawable` (XML)
    """
    try:
        with zipfile.ZipFile(apk_path) as z:
            with NamedTemporaryFile() as i:
                i.write(z.read(icon_path))
                img = Image.open(i.name).convert("RGBA")
                img.thumbnail(MAX_IMAGE_SIZE, Image.ANTIALIAS)
                buffer = BytesIO()
                img.save(buffer, format="PNG")
                data = base64.b64encode(buffer.getvalue()).decode('ascii')
                return data
    except Exception:
        return None


def _get_img_from_base64(base64_img):
    """
    Return a PIL `Image` object from a base64 encode image.
    :param base64_img: a base64 encode image
    :return: a PIL `Image` object
    """
    with NamedTemporaryFile() as i:
        i.write(base64.b64decode(base64_img))
        return Image.open(i.name).convert("RGBA")


def base64_to_icon(base64_icon):
    """
    Returns bytes the a base64 encoded image and converted into RGBA PNG.
    :param base64_icon: a base64 encoded image
    :return: bytes of the PNG format of the given image
    """
    try:
        with NamedTemporaryFile() as i:
            i.write(base64.b64decode(base64_icon))
            img = Image.open(i.name).convert("RGBA")
            buffer = BytesIO()
            img.save(buffer, format="PNG")
            return buffer.getvalue()
    except Exception:
        return None


def compute_dhash_from_base64(base64_img):
    """
    Computes the differential hash of a base64 encoded image.
    :param base64_img: a base64 encoded image
    :return: the differential hash in HEX format, None if `base64_img` is not a valid image
    """
    import dhash
    try:
        img = _get_img_from_base64(base64_img)
        return '{:02X}'.format(dhash.dhash_int(img, size=8))
    except Exception:
        return None


def compute_dhash_from_file(img_path):
    """
    Computes the differential hash of an image.
    :param img_path: the location of the image
    :return: the differential hash in HEX format, None if `img_path` is not a valid image
    """
    import dhash
    try:
        img = Image.open(img_path).convert("RGBA")
        return '{:02X}'.format(dhash.dhash_int(img, size=8))
    except Exception:
        return None


class ApplicationSignature(object):
    """
    ApplicationSignature object represents the signature of an APK containing:
    * handle: the application package name (handle)
    * app_name: the application name
    * uaid: the application unique identifier
    * version_name: the application version name string like '2.3.4'
    * version_code: the application version code integer like 2340
    * icon_hash: the icon differential hash involve in icon comparisons
    * apk_hash: the SHA256 sum the analyzed APK file
    * icon_base64: the application icon encoded in base64 scaled to 96x96px
    """

    def __init__(self):
        self.handle = None
        self.app_name = None
        self.uaid = None
        self.version_name = None
        self.version_code = None
        self.icon_hash = None
        self.apk_hash = None
        self.certificates = []
        self.icon_base64 = None
        self.md5 = None
        self.sha1 = None
        self.sha256 = None

    @staticmethod
    def compute_from_apk(apk_path):
        """
        Computes the signature of the APK located at the given path.
        :param apk_path: the location of the APK to be analyzed
        :return: the ApplicationSignature
        """
        apk = APK(apk_path)
        sign = ApplicationSignature()

        sign.handle = apk.get_package()
        sign.app_name = apk.get_app_name()
        sign.uaid = compute_uaid(apk)
        sign.version_name = apk.get_androidversion_name()
        sign.version_code = int(apk.get_androidversion_code())
        sign.apk_hash = get_sha256_of_file(apk_path)
        hashes = get_check_sums_of_file_as_dict(apk_path)
        sign.md5 = hashes['md5']
        sign.sha1 = hashes['sha1']
        sign.sha256 = hashes['sha256']
        sign.icon_base64 = icon_to_base64(apk_path, apk.get_app_icon())
        sign.icon_hash = compute_dhash_from_base64(sign.icon_base64)
        sign.certificates = get_certificates(apk)
        return sign

    @staticmethod
    def compute_from_url(url):
        """
        Downloads and computes the signature of the APK located at the given URL.
        :param url: the location of the APK to be analyzed
        :return: the ApplicationSignature, None if the URL is invalid
        """
        import urllib.request
        with NamedTemporaryFile() as apk:
            try:
                urllib.request.urlretrieve(url, apk.name)
                return ApplicationSignature.compute_from_apk(apk.name)
            except Exception:
                return None

    def to_dict(self):
        """
        Marshall the ApplicationSignature into a Python dict. This helper has to be called in order to pass an
        ApplicationSignature in parameter of a Celery task.
        :return: a Python dict
        """
        return {
            'handle': self.handle,
            'app_name': self.app_name,
            'uaid': self.uaid,
            'version_name': self.version_name,
            'version_code': self.version_code,
            'icon_hash': self.icon_hash,
            'apk_hash': self.apk_hash,
            'icon_base64': self.icon_base64,
            'sha1': self.sha1,
            'md5': self.md5,
            'certificates': [c.__dict__ for c in self.certificates]
        }

    @staticmethod
    def from_dict(d):
        """
        Unmarshall the Python dict into an ApplicationSignature. This helper has to be called in order to convert a
        Celery task result in ApplicationSignature object
        :return: unmarshalled ApplicationSignature object
        """
        signature = ApplicationSignature()
        signature.handle = d['handle']
        signature.app_name = d['app_name']
        signature.uaid = d['uaid']
        signature.version_name = d['version_name']
        signature.version_code = d['version_code']
        signature.icon_hash = d['icon_hash']
        signature.apk_hash = d['apk_hash']
        signature.icon_base64 = d['icon_base64']
        return signature

    def to_json_string(self):
        """
        Converts the ApplicationSignature into a JSON string.
        :return: the JSON string
        """
        import json
        return json.dumps(self.to_dict())
