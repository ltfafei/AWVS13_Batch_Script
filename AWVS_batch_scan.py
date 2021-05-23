#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import requests
import hashlib
import json
import argparse

#公众号:漏洞推送

#指定AWVS的URL和用户名密码
username = 'afei@xxx.com'
password = 'xxxxxx'
awvs_url = 'https://localhost:3443/'

class Awvs():
    awvs = ''
    headers = {
        'Content-Type': 'application/json;charset=UTF-8',
    }
    def __init__(self, awvs_url, username, password):
        self.awvs_url = awvs_url
        password = hashlib.sha256(password.encode()).hexdigest()
        info = {
            "email": username,
            "password": password,
            "remember_me": "false",
            "logout_previous":"true"
        }
        info = json.dumps(info)
        requests.packages.urllib3.disable_warnings()
        r = requests.session()
        try:
            X_Auth = r.post(self.awvs_url + 'api/v1/me/login', data=info, verify=False, headers=self.headers).headers['X-Auth']
        except:
            exit('awvs Login failed')
        self.headers['X-Auth'] = X_Auth
        self.awvs = r
    
    def addTarget(self,target_url):
        info = {
            "address": target_url,
            "description": '',
            'criticality':"10"
        }
        info = json.dumps(info)
        ret = self.awvs.post(self.awvs_url + 'api/v1/targets', data=info, verify=False, headers=self.headers).text
        ret = json.loads(ret)
        return ret['target_id']
    
    def scanTarget(self, target_id):
        info = '{"target_id":"xxxxxxxxxxxx","profile_id":"11111111-1111-1111-1111-111111111111","schedule":{"disable":false,"start_date":null,"time_sensitive":false},"ui_session_id":"81ae275a0a97d1a09880801a533a0ff1"}'
        info = info.replace('xxxxxxxxxxxx', target_id)
        self.awvs.post(self.awvs_url+'/api/v1/scans',data=info, verify=False, headers=self.headers).text
        

    def getScanList(self):
        scan_list= self.awvs.get(self.awvs_url + "/api/v1/scans?l=100", verify=False, headers=self.headers).text
        scan_list = json.loads(scan_list)
        scan_lists = []
        for i in scan_list['scans']:
            scan_lists.append(i['scan_id'])
        return scan_lists

    def getTargetList(self):
        target_list = self.awvs.get(self.awvs_url + "/api/v1/targets?l=100", verify=False, headers=self.headers).text
        target_list = json.loads(target_list)
        target_lists = []
        for i in target_list['targets']:
            target_lists.append(i['target_id'])
        return target_lists

    def delTarget(self, target_id):
        self.awvs.delete(self.awvs_url + "/api/v1/targets/" + target_id, verify=False, headers=self.headers)


    def delScan(self, scan_id):
        self.awvs.delete(self.awvs_url + "/api/v1/scans/" + scan_id, verify=False, headers=self.headers)
        
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
        
        
    
if __name__ == "__main__":
    awvs = Awvs(awvs_url, username, password)
    parser = argparse.ArgumentParser()
    parser.add_argument('-u',help='scan a url')
    parser.add_argument('-f',help='scan a file list')
    parser.add_argument('-g',help='add a group description')
    parser.add_argument('-d',action='store_true',help='delete all target and scan')
    args = parser.parse_args()
    if (args.u):
        target_id = awvs.addTarget(args.u)
        awvs.scanTarget(target_id)
        print('starting scan '+args.u)
    if (args.f):
        with open(args.f) as f:
            for i in f:
                url = i.replace("\n", '')
                url = url.replace("\r", '')
                target_id = awvs.addTarget(url)
                awvs.scanTarget(target_id)
                print('starting scan ' + url)
    
    
    if (args.g):
        targets_with_groups = awvs.name(args.u)
        awvs.patch_group(targets_with_groups)

    
    if (args.d):
        scan_list = awvs.getScanList()
        target_list = awvs.getTargetList()
        for i in scan_list:
            awvs.delScan(i)
        for i in target_list:
            awvs.delTarget(i)
        print('all delete success')
