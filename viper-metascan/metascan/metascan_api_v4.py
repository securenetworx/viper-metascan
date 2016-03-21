import requests
import time


class MetaScanApiError(Exception):
    def __init__(self, message):
        super(MetaScanApiError, self).__init__(message)
        self.message = message

    def __str__(self):
        return self.message


class MetaScanApiv4(object):
    """ MetaScan REST API. v4"""
    SCAN_RECHECK_DELAY = 2

    def __init__(self, ip, port):
        self.base_url = "%s:%d" % (ip, port)
        self.api_key = None
        try:
            requests.get(url='http://{}/stat/engines'.format(self.base_url), timeout=5)
        except requests.exceptions.Timeout:
            raise MetaScanApiError("Could not connect to MetaScan server [{0}:{1}].".format(ip, port))
        except requests.exceptions.RequestException as e:
            raise MetaScanApiError("MetaScan Error: {}".format(e))

    def login(self, name, passwd):
        url = 'http://{}/login'.format(self.base_url)
        params = {"user": name, "password": passwd}
        login = requests.post(url=url, json=params)
        self.api_key = login.json().get("session_id")
        if not self.api_key:
            raise MetaScanApiError("MetaScan login error. Check username and password.")

    def get_workflows(self):
        url = 'http://{}/file/workflows'.format(self.base_url)
        return requests.get(url=url)

    def scan_file(self, fd, filename='', workflow=''):
        url = 'http://{}/file'.format(self.base_url)
        headers = {"filename": filename}
        if workflow:
            headers["workflow"] = workflow
        with open(fd, 'rb') as ff:
            data = ff.read()
        return requests.post(url=url, data=data, headers=headers)

    def get_scan_results_by_data_id(self, data_id):
        url = 'http://{}/file/{}'.format(self.base_url, data_id)
        return requests.get(url=url)

    def scan_file_and_get_results(self, fd, filename='', workflow=''):
        response = self.scan_file(fd, filename, workflow)
        if response.status_code == requests.codes.ok:
            data_id = response.json()['data_id']
            sleep_delay = 0.2
            while True:
                response = self.get_scan_results_by_data_id(data_id=data_id)
                if response.status_code != requests.codes.ok:
                    return response
                if response.json().get('scan_results', {})['progress_percentage'] == 100:
                    break
                else:
                    time.sleep(min(sleep_delay, 2))
                    sleep_delay += 0.2
        return response

    def get_engines(self):
        url = 'http://{}/stat/engines'.format(self.base_url)
        return requests.get(url=url)

    def get_license(self):
        url = 'http://{}/admin/license'.format(self.base_url)
        headers = dict(apikey=self.api_key)
        return requests.get(url=url, headers=headers)
