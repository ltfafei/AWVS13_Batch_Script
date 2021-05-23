#!/usr/bin/python
# -*- coding: UTF-8 -*-

# wvs报告需要是alert item的html格式，生成的时候会提示
import re
import glob
import codecs
from bs4 import BeautifulSoup

result = codecs.open("count.csv", "w", 'utf-8')
tmp = "URL,High,Medium,Low,Informational"
result.write(tmp + "\n")
print(tmp.replace(",", " "))
for htmlfile in glob.glob(r'F:\工具\AWVS_console批量扫描\未知分组\*.html'):
    with open(htmlfile, encoding="utf-8") as f:
        html = f.read()
    tmp = ""
    soup = BeautifulSoup(html, "lxml")
    #print(soup)
    try:
        sites = soup.find_all(class_=re.compile('^s'), text="Alert group")
        print(sites)
        scanurl = re.compile(r"Start url</td>\n.+?((?:https|http|ftp|rtsp|mms)?:\/\/[^\s]+)</td>").findall(html)[0]
        tmp += scanurl + ","
        for i in ["High", "Medium", "Low", "Informational"]:
            tmp += re.compile(r'{}</td>\n?.*?<td>([^\s]+)</td>'.format(i)).findall(html)[0]
            tmp += ","
        result.write(tmp + "\n")
        print(tmp.replace(","," "))
       
    except Exception as e:
        print(e)
        #print(tmp)
result.close()
