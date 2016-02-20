import requests
import time


class MetaScanApiError(Exception):
    def __init__(self, message):
        super(MetaScanApiError, self).__init__(message)
        self.message = message

    def __str__(self):
        return self.message


class MetaScanApi(object):
    """ MetaScan REST API."""

    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.api_key = None
        try:
            requests.get(url='http://{0}:{1}/stat/engines'.format(self.ip, self.port), timeout=5)
        except requests.exceptions.Timeout:
            raise MetaScanApiError("Could not connect to MetaScan server [{0}:{1}].".format(self.ip, self.port))
        except requests.exceptions.RequestException as e:
            raise MetaScanApiError("MetaScan Error: {}".format(e))

    def login(self, name, passwd):
        url = 'http://{0}:{1}/login'.format(self.ip, self.port)
        params = {"user": name, "password": passwd}
        login = requests.post(url=url, json=params)
        self.api_key = login.json().get("session_id")
        if not self.api_key:
            raise MetaScanApiError("MetaScan login error. Check username and password.")

    def get_workflows(self):
        url = 'http://{0}:{1}/file/workflows'.format(self.ip, self.port)
        return requests.get(url=url)

    def scan_file(self, fd, filename='', workflow=''):
        url = 'http://{0}:{1}/file'.format(self.ip, self.port)
        headers = {"filename": filename}
        if workflow:
            headers["workflow"] = workflow
        with open(fd, 'rb') as ff:
            data = ff.read()
        return requests.post(url=url, data=data, headers=headers)

    def get_scan_results_by_data_id(self, data_id):
        url = 'http://{0}:{1}/file/{2}'.format(self.ip, self.port, data_id)
        return requests.get(url=url)

    def scan_file_and_get_results(self, fd, filename='', workflow=''):
        response = self.scan_file(fd, filename, workflow)
        if response.status_code == requests.codes.ok:
            data_id = response.json()['data_id']
            while True:
                response = self.get_scan_results_by_data_id(data_id=data_id)
                if response.status_code != requests.codes.ok:
                    return response
                if response.json().get('scan_results', {})['progress_percentage'] == 100:
                    break
                else:
                    time.sleep(3)
        return response

    def get_engines(self):
        url = 'http://{0}:{1}/stat/engines'.format(self.ip, self.port)
        return requests.get(url=url)

    def get_license(self):
        url = 'http://{0}:{1}/admin/license'.format(self.ip, self.port)
        headers = dict(apikey=self.api_key)
        return requests.get(url=url, headers=headers)
