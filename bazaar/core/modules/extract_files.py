from django.core.files.storage import default_storage
from tempfile import NamedTemporaryFile, TemporaryDirectory
import zipfile
import binwalkpy
import os
import gc
import logging
from django.conf import settings
from elasticsearch import Elasticsearch
from pathlib import PurePosixPath


es = Elasticsearch(
    settings.ELASTICSEARCH_HOSTS,
    request_timeout=30, max_retries=5,
    retry_on_timeout=True,
    basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD)
)


def analysis(sha256):
    es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'extract_files': 1}},
              retry_on_conflict=1)
    files = []
    try:
        with NamedTemporaryFile() as f:
            f.write(default_storage.open(sha256).read())
            f.seek(0)

            with TemporaryDirectory() as tmp_dir:
                apk = zipfile.ZipFile(f)

                file_list = apk.namelist()
                for member in file_list:
                    files.append(member)
                    apk.extract(member, tmp_dir)

                for file in files:
                    file = os.path.join(tmp_dir, file)
                    bw = binwalkpy.Binwalk(
                        target_file_name=file,
                        output_directory=os.path.join(tmp_dir, "_extracted"),
                        include=["dex", "elf", "zip"],
                        full_search=True,
                    )
                    extractions = bw.extract_file()
                    for e in extractions.values():
                        for fname in os.listdir(e['output_directory']):
                            fpath = os.path.join(e['output_directory'], fname)
                            if os.path.isfile(fpath):
                                print(f"\n\n\n\n\n\n\n{PurePosixPath(e["output_directory"]).name}\n\n\n\n\n\n\n")
                                with open(fpath, "rb") as f:
                                    default_storage.save(
                                        os.path.join(sha256, "extracted", f"{PurePosixPath(e["output_directory"]).name}_{fname}"),
                                        f
                                    )
                es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'extract_files': 2}},
                          retry_on_conflict=1)

    except Exception as e:
        logging.exception(e)
        es.update(index=settings.ELASTICSEARCH_TASKS_INDEX, id=sha256, body={'doc': {'extract_files': -1}},
                    retry_on_conflict=1)

    del apk, f
    gc.collect()

    return {'status': 'success', 'info': ''}