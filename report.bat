@echo off
echo --------------------------------------
echo AWVS����API����ɨ��ű�
echo --------------------------------------
echo �����������ر���...

::ÿ����վ���ɵ�������
py -3 awvs_console.py -a localhost -k 1986ad8c0a5b3df4d7028d5f3c06e936c565423fbe5454628a836ac8ff0a7b5b9 -r create_all_single

::�������ɵĵ�������
py -3 awvs_console.py -a localhost -k 1986ad8c0a5b3df4d7028d5f3c06e936c565423fbe5454628a836ac8ff0a7b5b9 -r download_all_single -d html