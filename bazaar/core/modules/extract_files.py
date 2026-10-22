from django.core.files.storage import default_storage
from tempfile import NamedTemporaryFile, TemporaryDirectory
import zipfile


def analysis(sha256):

    files = []
    with NamedTemporaryFile() as f:
        f.write(default_storage.open(sha256).read())
        f.seek(0)

        with TemporaryDirectory() as tmp_dir:
            apk = zipfile.ZipFile(f)

            file_list = apk.namelist()
            for member in file_list:
                if member == "classes.dex":
                    continue
                try:
                    files.append(member)
                    apk.extract(member, tmp_dir)
                except Exception as e:
                    logging.error('Can not extract member: %s due to an error %s', member, e)

            for file in files:
                pass
                # run extractor
                # if found elf, jar, dex
                #    save to default_storage + link for download

    del apk, f
    gc.collect()

    return {'status': 'success', 'info': ''}