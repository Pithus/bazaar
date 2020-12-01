import requests

import logging

logger = logging.getLogger(__name__)

DEFAULT_SERVER = 'http://127.0.0.1:8000'


class MobSF:
    """Represents a MobSF instance."""

    def __init__(self, apikey, server=None):
        self.__server = server if server else DEFAULT_SERVER
        self.__apikey = apikey
        self.hash = {'hash': None}

    @property
    def server(self):
        return self.__server

    @property
    def apikey(self):
        return self.__apikey

    def upload(self, filename, file):
        """Upload an app."""
        logger.debug(f"Uploading {filename} to {self.__server}")

        multipart_data ={'file': (filename, file, 'application/octet-stream')}
        headers = {'Authorization': self.__apikey}

        r = requests.post(f'{self.__server}/api/v1/upload', files=multipart_data, headers=headers)

        if r.status_code == 200:
            response = r.json()
            self.hash = {"hash": response["hash"]}
            return response

        print(r.text)

        return None

    def scan(self, data):
        """Scan already uploaded file.
        If the file was not uploaded before you will have to do so first.
        """
        logger.debug(f"Requesting {self.__server} to scan {data['hash']}")
        headers = {'Authorization': self.__apikey}
        r = requests.post(f'{self.__server}/api/v1/scan', data=data, headers=headers)
        return r.json()

    def scans(self, page=1, page_size=100):
        """Show recent scans."""
        logger.debug(f'Requesting recent scans from {self.__server}')

        payload = {'page': page,
                   'page_size': page_size}
        headers = {'Authorization': self.__apikey}

        r = requests.get(f'{self.__server}/api/v1/scans', params=payload, headers=headers)

        return r.json()

    def report_json(self, data):
        """Retrieve JSON report of a scan."""
        logger.debug(f'Requesting JSON report for scan {data["hash"]}')
        headers = {'Authorization': self.__apikey}
        data = {'hash': data['hash']}
        r = requests.post(f'{self.__server}/api/v1/report_json', data=data, headers=headers)

        return r.json()

    def delete_scan(self, data):
        """Delete a scan result."""
        logger.debug(f'Requesting {self.__server} to delete scan {data["hash"]}')

        headers = {'Authorization': self.__apikey}
        data = {'hash': data["hash"]}

        r = requests.post(f'{self.__server}/api/v1/delete_scan', data=data, headers=headers)

        return r.json()
