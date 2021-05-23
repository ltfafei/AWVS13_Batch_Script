@echo off
echo --------------------------------------
echo AWVS调用API批量扫描脚本
echo --------------------------------------
echo 正在添加任务...

py -3 awvs_console.py -a localhost -k 1986ad8c0a5b3df4d7028d5f3c06e936c7ba11cf78a694334b01a5aa511dfca91  -f "D:\penetration testing\All-sec\20210506-20210514\湖南快乐阳光互动娱乐传媒有限公司\mgtv.com子域名_Layer.txt" -g 芒果TV -s
pause