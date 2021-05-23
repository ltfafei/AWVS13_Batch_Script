@echo off
echo --------------------------------------
echo AWVS调用API批量扫描脚本
echo --------------------------------------
echo 正在添加任务...

py -3 awvs_console.py -a localhost -k 198xxxxxxxxxxxx4b01a5aa511dfca91  -f "Layer.txt" -g xxx -s
pause
