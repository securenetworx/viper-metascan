import requests
import time


class MetaScanApiError(Exception):
    def __init__(self, message):
        super(MetaScanApiError, self).__init__(message)
        self.message = message

    def __str__(self):
        return self.message


class MetaScanApiv3(object):
    """ MetaScan REST API v3."""

    def __init__(self, ip, port, api_key=None, user_agent=None):
        self.base_url = "%s:%d/metascan_rest" % (ip, port)
        self.api_key = api_key
        self.user_agent = user_agent
        headers = ""
        if self.api_key:
            headers = {"apikey": self.api_key}
        try:
            requests.get(url='http://{0}/stat/engines'.format(self.base_url), headers=headers, timeout=5)
        except requests.exceptions.Timeout:
            raise MetaScanApiError("Could not connect to MetaScan server [{0}:{1}].".format(ip, port))
        except requests.exceptions.RequestException as e:
            raise MetaScanApiError("MetaScan Error: {0}".format(e))

    def send_post(self, url, headers=None, data=None):
        headers = headers or {}
        if self.api_key:
            headers["apikey"] = self.api_key
        return requests.post(url=url, data=data, headers=headers)

    def send_get(self, url, headers=None):
        headers = headers or {}
        if self.api_key:
            headers = {"apikey": self.api_key}
        return requests.get(url=url, headers=headers)

    def scan_file(self, fd, filename=''):
        url = 'http://{0}/file'.format(self.base_url)
        headers = {"filename": filename}
        if self.user_agent:
            headers["user_agent"] = self.user_agent
        with open(fd, 'rb') as ff:
            data = ff.read()
        return self.send_post(url, headers, data)

    def get_scan_results_by_data_id(self, data_id):
        url = 'http://{0}/file/{1}'.format(self.base_url, data_id)
        return self.send_get(url=url)

    def scan_file_and_get_results(self, fd, filename=''):
        response = self.scan_file(fd, filename)
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
        url = 'http://{0}/stat/engines'.format(self.base_url)
        return self.send_get(url=url)
