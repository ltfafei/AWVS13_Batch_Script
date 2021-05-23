#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

"""
@File       : awvs_scan.py
@Author     : Ctxer
@Contact    : admin@tulst.com
"""

# import lib
import io
import os
import re
import sys
import ssl
import json
import gzip
import time
import getopt
import urllib.request


class HttpClient(object):
    def __init__(self, header):
        self.header = header
        assert "Accept-Encoding" in self.header, "Accept-Encoding must in Request Header"

    def _gzip_decode(self, data):
        gziper = gzip.GzipFile(fileobj=io.BytesIO(data))
        return gziper.read()

    def _make_data(self, **kwargs):
        return bytes(json.dumps(kwargs), self.header["Accept-Encoding"])

    def _make_response(self, **kwargs):
        request = urllib.request.Request(**kwargs, headers=self.header)  # url,data
        return urllib.request.urlopen(request, context=ssl._create_unverified_context())

    def _url_open(self, **kwargs):
        response = self._make_response(**kwargs)
        if response.getheader('Content-Encoding') == "gzip":
            return self._gzip_decode(response.read())
        else:
            return response.read().decode(response.getheader('Content-Encoding') or self.header["Accept-Encoding"])

    def _api_open(self, **kwargs):
        return json.loads(self._url_open(**kwargs))

    def _add_get_params(self, **kwargs):
        res = "?"
        for k, v in kwargs.items():
            if v is not None: res += "%s=%s&" % (k, v)
        return res[:-1]


class AWVS_L_API(HttpClient):
    def __init__(self, host, api_key, *, port=3443, coding="utf-8", user_agent="", **kwargs):
        self.host = host
        self.port = port
        self.api_key = api_key
        self.url = "https://{0}:{1}/".format(self.host, self.port)
        super(AWVS_L_API, self).__init__({
            "X-Auth": self.api_key,
            "Content-Type": "application/json",
            "Accept-Encoding": coding,
            'User-Agent': user_agent
        })

    def create_target(self, address, description, int_criticality=10):
        data = self._make_data(address=address, description=description, criticality=int_criticality)
        return self._api_open(url=self.url + "api/v1/targets", data=data)

    def delete_target(self, target_id):
        return self._api_open(url=self.url + "api/v1/targets/" + target_id, method="DELETE")

    def _get_base_with_id(self, url, id="", *, q=None, c=None, l=None, **kwargs):
        if id:
            id = "/" + id
        return self._api_open(url=self.url + url + id + self._add_get_params(q=q, c=c, l=l), **kwargs)

    def get_targets(self, target_id="", *, q=None, c=None, l=None, **kwargs):
        return self._get_base_with_id("api/v1/targets", target_id, q=q, c=c, l=l, **kwargs)

    def get_scanning_profiles(self):
        return self._url_open(url=self.url + "api/v1/scanning_profiles")

    def get_scans(self, scan_id="", *, q=None, c=None, l=None, **kwargs):
        return self._get_base_with_id("api/v1/scans", scan_id, q=q, c=c, l=l, **kwargs)

    def start_scan(self, target_id, profile_id, schedule):
        data = self._make_data(target_id=target_id, profile_id=profile_id, schedule=schedule)
        return self._api_open(url=self.url + "api/v1/scans", data=data)

    def stop_scan(self, target_id):
        return self._api_open(url=self.url + "api/v1/scans/" + target_id + "/abort")

    def delete_scan(self, target_id):
        return self._api_open(url=self.url + "api/v1/scans/" + target_id + "/abort", method="DELETE")

    def target_status(self, target_id):
        return self._api_open(url=self.url + "api/v1/targets/" + target_id)

    def get_target_result(self, last_scan_id, scan_session_id):
        return self._api_open(
            url=self.url + "api/v1/scans/" + last_scan_id + "/results/" + scan_session_id + "/vulnerabilities")

    def get_result_vuln(self, last_scan_id, scan_session_id, vuln_id):
        return self._api_open(
            url=self.url + "api/v1/scans/" + last_scan_id + "/results/" + scan_session_id + "/vulnerabilities" + "/" + vuln_id)

    def get_result_response(self, last_scan_id, scan_session_id, vuln_id):
        try:
            return self._url_open(
                url=self.url + "api/v1/scans/" + last_scan_id + "/results/" + scan_session_id + "/vulnerabilities" + "/" + vuln_id + "/http_response")
        except:
            return ""

    def info(self):
        return self._api_open(url=self.url + "api/v1/info")

    def me(self):
        return self._api_open(url=self.url + "api/v1/me")

    def get_scanning_profiles(self):
        return self._api_open(url=self.url + "api/v1/scanning_profiles")

    def get_vuln(self, vuln_id):
        return self._api_open(url=self.url + "api/v1/vulnerabilities/" + vuln_id)

    def consume_all(self):
        return self._url_open(url=self.url + "api/v1/notifications/consume", method="POST")

    def get_target_groups(self, *, c=None):
        return self._api_open(url=self.url + "api/v1/target_groups" + self._add_get_params(c=c), method="GET")

    def create_target_group(self, name, description):
        data = self._make_data(name=name, description=description)
        return self._api_open(url=self.url + "api/v1/target_groups", method="POST", data=data)

    def patch_target_group(self, group_id, add=[], remove=[]):
        data = self._make_data(add=add, remove=remove)
        return self._api_open(url=self.url + "api/v1/target_groups/%s/targets" % group_id, method="PATCH", data=data)

    def delete_report(self, report_id):
        return self._url_open(url=self.url + "api/v1/reports/" + report_id, method="DELETE")

    def create_report(self, template_id, list_type, id_list):
        data = self._make_data(template_id=template_id, source={"list_type": list_type, "id_list": id_list})
        return self._api_open(url=self.url + "api/v1/reports", method="POST", data=data)

    def get_reports(self, report_id="", *, q=None, c=None, l=None, **kwargs):
        return self._get_base_with_id("api/v1/reports", report_id, q=q, c=c, l=l, **kwargs)

    def download_report(self, report_path):
        return self._make_response(url=self.url + report_path, method="GET").read()


def read_targets(fn):
    with open(fn, "r+", errors="ignore") as f:
        return [i.strip() for i in f.readlines()]


def read_group_targets(fn, s="|"):
    return [i.split(s) for i in read_targets(fn) if s in i]


def save_data(fn, data):
    print("[!] 存储报告文件 `%s`" % fn)
    with open(fn, "wb+") as f:
        f.write(data)


def make_dirs(groups):
    path = os.getcwd()
    for i in groups:
        dir = os.path.join(path, i)
        if not os.path.exists(dir):
            print("[!] 创建分类目录 `%s`" % dir)
            os.mkdir(dir)


def path_join(*args):
    path = os.getcwd()
    for i in args:
        path = os.path.join(path, i)
    return path


def be_can_save(fn):
    for i in ("\\", "/", ":", "*", "?", "<", ">", "|"):
        fn = fn.replace(i, "")
    return fn


def check_params(*args):
    for k, v in args:
        if k not in v:
            print("[-] 参数 `%s` 必须是 %s 其中之一" % (k, v))
            sys.exit(-1)
            # print("\033[31m[-] 参数 `%s` 必须是 %s 其中之一\033[31;m" % (k, v))


def get_url_domain(url):
    try:
        domain = re.compile("(?:https?://)?([^/]+)/?\S*", re.I).findall(url)
        # assert len(domain) == 1, print(domain) + sys.exit(2)
        return domain[0]
    except:
        return url


class AWVS_H_API(object):
    def __init__(self, *args, **kwargs):
        self.awvs = AWVS_L_API(*args, **kwargs)

    def scan(self, i, desception, *, profile_id="11111111-1111-1111-1111-111111111111",
             schedule={"disable": False, "start_date": None, "time_sensitive": False}):
        target = self.awvs.create_target(i, "[%s]-[%s]" % (desception, time.asctime(time.localtime(time.time()))))
        target_id = target["target_id"]
        self.awvs.start_scan(target_id, profile_id, schedule)

    def clear_targets(self):
        for i in self.get_all_without_cursor("get_targets", "targets"):
            self.awvs.delete_target(i["target_id"])

    def clear_scans(self):
        for i in self.get_all_without_cursor("get_scans", "scans"):
            self.awvs.delete_scan(i["scan_id"])

    def clear_reports(self):
        for i in self.get_all_without_cursor("get_reports", "reports"):
            self.awvs.delete_report(i["report_id"])

    def get_all_without_cursor(self, func_name, keyword, **kwargs):
        res, c = [], None
        while True:
            ts = self.awvs.__getattribute__(func_name)(c=c, **kwargs)
            res.extend(ts[keyword])
            if ts["pagination"]["next_cursor"] is None:
                break
            else:
                c = ts["pagination"]["next_cursor"]
        return res

    def patch_group(self, targets_with_groups):
        targets = {}
        groups = {}

        for i in self.get_all_without_cursor("get_target_groups", "groups"):
            groups[i["name"]] = i["group_id"]

        for group in set([i[1] for i in targets_with_groups]):
            if group not in groups:
                self.awvs.create_target_group(group, "")

        for i in self.get_all_without_cursor("get_target_groups", "groups"):
            groups[i["name"]] = i["group_id"]

        for i in self.get_all_without_cursor("get_targets", "targets"):
            targets[i["address"]] = i["target_id"]

        success, failed = [], []
        for t in targets_with_groups:
            if t[0] in targets and t[1] in groups:
                success.append(t)
                try:
                    self.awvs.patch_target_group(groups[t[1]], [targets[t[0]]])
                except:
                    pass
            else:
                failed.append(t)
        return success, failed

    def get_groups_convert(self, keyword, *, keyword_wapper=str):
        groups_convert = {}
        for group in self.get_all_without_cursor("get_target_groups", "groups"):
            for target in self.get_all_without_cursor("get_targets", "targets", q="group_id:" + group["group_id"]):
                groups_convert[keyword_wapper(target[keyword])] = group["name"]
        return groups_convert

    def create_all_single_report(self, template_id, list_type="targets", *,
                                 list_types={"targets": "target_id", "scans": "scan_id"}):
        check_params([list_type, list_types])
        scan_ids = []
        for i in self.get_all_without_cursor("get_" + list_type, list_type):
            scan_ids.append(i[list_types[list_type]])
        for i in scan_ids:
            self.awvs.create_report(template_id, list_type, [i])

    def download_all_single_report(self, *, download_type="html", list_type="targets",
                                   download_types={"html": 0, "pdf": 1},
                                   list_types={"targets": "target_id", "scans": "scan_id"}):
        check_params([list_type, list_types], [download_type, download_types])
        groups = self.get_groups_convert("address", keyword_wapper=get_url_domain)
        scan_ids = {}
        make_dirs(set(
            [be_can_save(group["name"]) for group in self.get_all_without_cursor("get_target_groups", "groups")] + [
                "未知分组"]))
        for i in self.get_all_without_cursor("get_" + list_type, list_type):
            scan_ids[i[list_types[list_type]]] = i.get("address") or i.get("target", {}).get("address")
        for report in self.get_all_without_cursor("get_reports", "reports"):
            if report["source"]["list_type"] == list_type and report["status"] == "completed" and not report["source"][
                "description"].startswith("Multiple"):
                # print(report["source"]["description"])
                domain = get_url_domain(report["source"]["description"].split(";")[0])
                # print(domain)
                save_data(path_join(groups.get(domain, "未知分组"), be_can_save(domain) + "." + download_type),
                          self.awvs.download_report(report["download"][download_types[download_type]]))

    def create_all_group_report(self, template_id, list_type="targets", *,
                                list_types={"targets": "target_id", "scans": "scan_id"}):
        check_params([list_type, list_types])
        for group in self.get_all_without_cursor("get_target_groups", "groups"):
            scan_ids = [i[list_types[list_type]] for i in
                        self.get_all_without_cursor("get_" + list_type, list_type,
                                                    q="group_id:" + group["group_id"])]
            self.awvs.create_report(template_id, list_type, scan_ids)

    def download_all_group_report(self, *, list_type="targets", download_type="html",
                                  download_types={"html": 0, "pdf": 1},
                                  list_types={"targets": "target_id", "scans": "scan_id"}):
        check_params([list_type, ["targets", "scans"]], [download_type, download_types])
        groups = self.get_groups_convert(list_types[list_type])
        for report in self.get_all_without_cursor("get_reports", "reports"):
            if report["source"]["list_type"] == list_type and report["status"] == "completed" and report["source"][
                "description"].startswith("Multiple"):
                for i in report["source"]["id_list"]:
                    group_name = groups.get(i)
                    if group_name is not None:
                        break
                else:
                    group_name = report["report_id"]
                save_data(path_join(be_can_save(group_name) + "." + download_type),
                          self.awvs.download_report(report["download"][download_types[download_type]]))

    def uncomputed_report(self):
        return [report["report_id"] for report in self.get_all_without_cursor("get_reports", "reports") if
                report["status"] == "queued" or report["status"] == "processing"]

    def automation_all_group_report(self, template_id, *, download_type="html",
                                    list_type="targets", download_types={"html": 0, "pdf": 1},
                                    list_types={"targets": "target_id", "scans": "scan_id"}):
        check_params([list_type, list_types], [download_type, download_types])

        for group in self.get_all_without_cursor("get_target_groups", "groups"):
            if len(self.uncomputed_report()) > 0:
                print("[-] 发现不明生成中报告，程序将退出")
                sys.exit(-1)

            scan_ids = [i[list_types[list_type]] for i in
                        self.get_all_without_cursor("get_" + list_type, list_type, q="group_id:" + group["group_id"])]
            self.awvs.create_report(template_id, list_type, scan_ids)
            report_id = self.uncomputed_report()[0]
            while True:
                report = self.awvs.get_reports(report_id)
                if report["status"] == "completed":
                    save_data(path_join(be_can_save(group["name"]) + "." + download_type),
                              self.awvs.download_report(report["download"][download_types[download_type]]))
                    break
                elif report["status"] == "failed":
                    print(group["name"], end=":")
                    print(report["status"])
                    break


USAGE = \
    '''
                                                          
       _  __        ____     __ ____           ____                            _    Ver:1.6.2     
      / \ \ \      / /\ \   / // ___|         / ___|  ___   _ __   ___   ___  | |  ___ 
     / _ \ \ \ /\ / /  \ \ / / \___ \  _____ | |     / _ \ | '_ \ / __| / _ \ | | / _ \\
    / ___ \ \ V  V /    \ V /   ___) ||_____|| |___ | (_) || | | |\__ \| (_) || ||  __/
   /_/   \_\ \_/\_/      \_/   |____/         \____| \___/ |_| |_||___/ \___/ |_| \___|


   Usage:
          -a --address    <awvs_address>          AWVS所在机的ip地址(必须填)
          -p --port       <awvs_port>             AWVS的WEB端口
          -k --key        <awvs_api_key>          AWVS的API KEY(必须填)
          -t --target     <target>                要扫描的目标
          -f --file       <target_list_file>      要扫描的目标列表(按行分割)
          -r --report     <report_type>           指定所需漏扫报告的操作:
                                                      create_all_single:      生成所有单个网站的扫描报告
                                                      download_all_single:    下载所有单个网站的扫描报告
                                                      create_all_groups:      生成所有分组下属的混合扫描报告
                                                      download_all_groups:    下载所有分组下属的混合扫描报告
                                                      automation_all_groups:  自动生成下载所有分组下属的混合扫描报告
          -d --download   <download_type>         指定下载报告的类型:
                                                      pdf:    下载pdf格式的报告（默认）
                                                      html:   下载html格式的报告
          -c --clear      <need_clear_range>      清空指定范围的执行结果:
                                                      reports:    清空所有已生成的扫描报告
                                                      targets:    清空所有已添加的扫描目标
                                                      scans:      清空所有已扫描的扫描结果
          -g --group                              扫描任务分组，需配-f --file使用(文件格式需如下:127.0.0.1|测试)
          -s --scan                               添加目标并扫描
   '''


def main(argv):
    awvs_api_address, awvs_port = None, 3443
    awvs_api_key, targets = None, []
    clean_type, report_type = None, None
    need_scan, need_group = False, False
    templete_id, download_type = "11111111-1111-1111-1111-111111111111", "pdf"

    if argv == []:
        argv.append("-h")
    try:
        opts, args = getopt.getopt(argv, "hsga:p:k:t:f:c:r:d:",
                                   ["help", "scan", "group", "address=", "port=", "key=", "target=", "file=",
                                    "clean=", "report=", "download="])
    except getopt.GetoptError:
        print(USAGE)
        sys.exit(0)
    for opt, arg in opts:
        # print(opt,arg)
        if opt in ("-h", "--help"):
            print(USAGE)
            sys.exit()
        elif opt in ("-a", "--address"):
            awvs_api_address = arg
        elif opt in ("-p", "--port"):
            awvs_port = arg
        elif opt in ("-k", "--key"):
            awvs_api_key = arg
        elif opt in ("-t", "--target"):
            targets.append(arg)
        elif opt in ("-f", "--file"):
            targets.extend(read_group_targets(arg))
        elif opt in ("-c", "--clean"):
            clean_type = arg
        elif opt in ("-r", "--report"):
            report_type = arg
        elif opt in ("-d", "--downlod"):
            download_type = arg
        elif opt in ("-s", "--scan"):
            need_scan = True
        elif opt in ("-g", "--group"):
            need_group = True
    assert awvs_api_address is not None, print("[-] 缺失AWVS WEB API的地址。请指定-a --address") + sys.exit(0)
    assert awvs_api_key is not None, print("[-] 缺失AWVS API KEY。请指定-k --key") + sys.exit(0)
    awvs_h_api = AWVS_H_API(awvs_api_address, port=awvs_port, api_key=awvs_api_key)
    if clean_type:
        if clean_type == "scans":
            awvs_h_api.clear_scans()
        elif clean_type == "reports":
            awvs_h_api.clear_reports()
        elif clean_type == "targets":
            awvs_h_api.clear_targets()
    if need_scan:
        for i in targets:
            awvs_h_api.scan(*i)
        awvs_h_api.awvs.consume_all()
    if need_group:
        assert targets is not [], print("[-] 缺失目标分组信息。请指定-f --file") + sys.exit(0)
        awvs_h_api.patch_group(targets)
    if report_type:
        check_params([download_type, ["pdf", "html"]])
        check_params([report_type,
                      ["create_all_single", "download_all_single", "create_all_groups", "download_all_groups",
                       "automation_all_groups"]])
        if report_type == "create_all_single":
            awvs_h_api.create_all_single_report(templete_id)
        elif report_type == "download_all_single":
            awvs_h_api.download_all_single_report(download_type=download_type)
        elif report_type == "create_all_groups":
            awvs_h_api.create_all_group_report(templete_id)
        elif report_type == "download_all_groups":
            awvs_h_api.download_all_group_report(download_type=download_type)
        elif report_type == "automation_all_groups":
            awvs_h_api.automation_all_group_report(templete_id, download_type=download_type)


if __name__ == "__main__":
    main(sys.argv[1:])
