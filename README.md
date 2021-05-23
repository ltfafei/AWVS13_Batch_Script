# AWVS13_Batch_Script
AWVS13 batch scan Script

Resources：https://afei00123.blog.csdn.net/article/details/117186981

## 1.awvs_console.py

python.exe .\awvs_console.py -h

       _  __        ____     __ ____           ____                            _    Ver:1.6.2
...


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

添加扫描：
py -3 awvs_console.py -a localhost -k <api-key>  -f .\Batch_url\xxx.txt -s

![image](https://user-images.githubusercontent.com/43526141/119246328-49679f80-bbb3-11eb-86ea-34b1029abe6d.png)
       
       
## 2.AWVS_batch_scan.py
python .\AWVS_batch_scan.py -h
       
usage: AWVS_batch_scan.py [-h] [-u U] [-f F] [-g G] [-d]

optional arguments:
       
         -h, --help  show this help message and exit

         -u U        scan a url

         -f F        scan a file list

         -g G        add a group description

         -d          delete all target and scan
