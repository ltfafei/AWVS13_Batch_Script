@echo off
echo --------------------------------------
echo AWVS调用API批量扫描脚本
echo --------------------------------------
echo 正在生成下载报表...

::每个网站生成单个报表
py -3 awvs_console.py -a localhost -k 1986ad8c0a5b3df4d7028d5f3c06e936c565423fbe5454628a836ac8ff0a7b5b9 -r create_all_single

::下载生成的单个报表
py -3 awvs_console.py -a localhost -k 1986ad8c0a5b3df4d7028d5f3c06e936c565423fbe5454628a836ac8ff0a7b5b9 -r download_all_single -d html