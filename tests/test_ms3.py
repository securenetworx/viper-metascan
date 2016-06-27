import mock
import requests_mock
import sys

sys.path.append("viper-metascan")
from metascan import metascan_api_v3

PYBUILTINS = "builtins"
if sys.version_info[0] < 3:
    PYBUILTINS = "__builtin__"



class TestMetaScanApiV4(object):

    def setup_method(self, method):
        self.ms_host = "localhost"
        self.ms_port = 8888
        self.ms_api_key = "apikey"
        self.ms_user_agent = "useragent"
        self.ms_url = "http://%s:%d/metascan_rest" % (self.ms_host, self.ms_port)
        with requests_mock.mock() as m:
            m.get('%s/stat/engines' % self.ms_url, text='')
            self.metascan = metascan_api_v3.MetaScanApiv3(self.ms_host, self.ms_port, self.ms_api_key, self.ms_user_agent)

    def test_scan_file(self):
        data_id = "fakedataid"
        with requests_mock.mock() as m:
            m.post('%s/file' % self.ms_url, text='{"data_id":"%s"}' % data_id)
            with mock.patch('%s.open' % PYBUILTINS, mock.mock_open()):
                resp = self.metascan.scan_file("fake/file/path", "fake_file_name")
                assert resp.json()["data_id"] == data_id

    def test_get_scan_results_by_data_id(self):
        data_id = "fakedataid"
        scan_res = '{"date_id":"%s"}' % data_id
        with requests_mock.mock() as m:
            m.get('%s/file/%s' % (self.ms_url, data_id), text=scan_res)
            resp = self.metascan.get_scan_results_by_data_id(data_id)
            assert resp.text == scan_res

    def test_scan_file_and_get_result(self):
        data_id = "fakedataid"
        scan_res = '{"scan_results":{"progress_percentage":100}}'
        with requests_mock.mock() as m:
            m.post('%s/file' % self.ms_url, text='{"data_id":"%s"}' % data_id)
            m.get('%s/file/%s' % (self.ms_url, data_id), text=scan_res)
            resp = self.metascan.get_scan_results_by_data_id(data_id)
            with mock.patch('%s.open' % PYBUILTINS, mock.mock_open()):
                resp = self.metascan.scan_file_and_get_results("fake/file/path", "fake_file_name")
                assert resp.text == scan_res
