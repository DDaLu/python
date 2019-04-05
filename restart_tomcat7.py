# -*- coding:utf-8 -*-
# !/usr/bin/env python3

 
"""
重启tomcat7；
"""
 
import os
import sys
import time
import glob
import telnetlib
 
 
 
# 重启tomcat服务器----------------------------------------------------------
def restart():
    os.system("sudo /etc/init.d/tomcat7 restart")
    os.system("gzygkl305")
 
 
 
 
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    print("开始定时重启tomcat7！")
    while True:
       time_now = time.strftime("%H:%M", time.localtime())  # 刷新
       if time_now == "00:00": #此处设置每天定时的时间
           subject = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())+ "    tomcat7重启成功！"
           restart()
           print(subject)
           time.sleep(50)

       if time_now == "12:00": #此处设置每天定时的时间
           subject = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())+ "    tomcat7重启成功！"
           restart()
           print(subject)
           time.sleep(50)
           
