import sys

try:
    from viper.common.abstracts import Module
    from viper.core.session import __sessions__
    from viper.core.storage import get_sample_path
except ImportError:
    # These for testing
    sys.path.append("../")
    from viper.common.abstracts import Module
    from viper.core.session import __sessions__
    from viper.core.storage import get_sample_path

try:
    from dateutil import parser
    HAVE_DATEUTIL = True
except ImportError:
    HAVE_DATEUTIL = True

try:
    from requests.exceptions import HTTPError
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = True

from terminaltables import AsciiTable
from metascan import metascan_api_v3


HOST = ""
PORT = 8009
API_KEY = ""
USER_AGENT = ""


def dequote(s):
    if (s[0] == s[-1]) and s.startswith(("'", '"')):
        return s[1:-1]
    return s


class MetaScan(Module):
    cmd = 'ms3'
    description = 'Metadefender Core (Metascan v3) analysis module. (c) 2016 Secure Networx Ltd.'
    authors = ['Balint Kovacs', 'kovacsbalu']

    def __init__(self):
        super(MetaScan, self).__init__()
        if not HAVE_DATEUTIL:
            self.log('error', "Missing dependency, install dateutil (`pip install python-dateutil>=2.2`)")
        if not HAVE_REQUESTS:
            self.log('error', "Missing dependency, install requests (`pip install requests>=2.9.1`)")

        self.parser.add_argument('-f', '--find', help='Analyze all found items', action='store_true')
        self.parser.add_argument('-e', '--engines', help='List engines', action='store_true')
        self.parser.add_argument('-u', '--user_agent', help='Set user_agent header', default=USER_AGENT)

        self.files = []
        self.was_api_error = False

        try:
            self.metascan = metascan_api_v3.MetaScanApiv3(HOST, PORT, API_KEY, USER_AGENT)
        except metascan_api_v3.MetaScanApiError as err:
            self.log('error', err)
            self.was_api_error = True

    def run(self):
        super(MetaScan, self).run()

        if self.was_api_error:
            return

        if self.args:
            if self.args.user_agent:
                self.metascan.user_agent = self.args.user_agent
            if self.args.engines:
                self.show_engines()
            elif self.args.find:
                if not __sessions__.find:
                    self.log('error', "No find result")
                    return
                self.files = self.get_files_from_last_find()
            else:
                if not __sessions__.is_set():
                    self.log('error', "No session opened")
                    return
                self.files = self.get_file_from_current_session()
            if self.files:
                summary = self.show_analyzed_info()
                self.show_summary(summary)

    def get_files_from_last_find(self):
        files = []
        if __sessions__.find:
            for item in __sessions__.find:
                path = get_sample_path(item.sha256)
                files.append((path, item.name))
        return files

    def get_file_from_current_session(self):
        curr = __sessions__.current
        return [(curr.file.path, curr.file.name)]

    def show_analyzed_info(self):
        summary_table = [["Filename", "md5", "status"]]
        for path, name in self.files:
            av_found_threat = 0
            details = [["Engine", "Threat", "Def. time"]]
            res = self.metascan.scan_file_and_get_results(path, name)
            try:
                res.raise_for_status()
            except HTTPError as err:
                self.log('error', err)
                return
            jres = res.json()
            if jres.get("process_info", {}).get("result") == "Blocked":
                details = [["Blocked", "Reason: %s " % jres["process_info"]["blocked_reason"]]]
                status = "blocked"
            else:
                for engine, scan_details in jres["scan_results"]["scan_details"].iteritems():
                    if scan_details.get("scan_result_i"):
                        av_found_threat += 1
                    def_time = parser.parse(scan_details["def_time"]).strftime("%Y-%m-%d %H:%M:%S")
                    details.append([engine, scan_details["threat_found"], def_time])
                status = "%d/%d" % (av_found_threat, jres["scan_results"]["total_avs"])
            summary_table.append([name, jres["file_info"]["md5"], status])
            table = AsciiTable(details, name)
            print table.table
        return summary_table

    def show_summary(self, summary_table):
        sum_table = AsciiTable(summary_table, "Summary")
        print sum_table.table

    def show_engines(self):
        details = [["Engine name", "Engine version", "Def time", "Active"]]
        engines = self.metascan.get_engines()
        try:
            engines.raise_for_status()
        except HTTPError as err:
            self.log('error', err)
            return
        for eng in engines.json():
            def_time = parser.parse(eng["def_time"]).strftime("%Y-%m-%d %H:%M:%S")
            active = "Y" if eng["active"] else "N"
            details.append([eng["eng_name"], eng["eng_ver"], def_time, active])
        table = AsciiTable(details, "Engines")
        print table.table


if __name__ == "__main__":
    print "--- Test ---"
    ms = MetaScan()
    ms.show_engines()
