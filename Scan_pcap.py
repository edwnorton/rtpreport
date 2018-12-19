#!C:\Users\edify\AppData\Local\Programs\Python\Python36
# -*- coding: utf-8  -*-
import configparser
import os
import re
import time,queue,datetime
import logging
import multiprocessing
import threading
from multiprocessing.managers import BaseManager

conf = configparser.ConfigParser()
conf.read("C:\\rtpstream\\conf.ini")
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)
source_dir = conf.get("dir", "source_file_dir")
source_dir_rtp = conf.get("dir", "source_file_dir_rtp")
#dt = datetime.datetime.now()
#dst = dt.strftime('%Y%m%d')
#source_dir_day = os.path.join(source_dir,dst)

#分布式进程master程序
class QueueManager(BaseManager):
    pass
task_queue = queue.Queue()
result_queue = queue.Queue()
rtpstream_queue = queue.Queue()
def return_task_queue():
    global task_queue
    return task_queue
def return_result_queue():
    global result_queue
    return result_queue
def return_rtpstream_queue():
    global rtpstream_queue
    return rtpstream_queue
if __name__ == '__main__':
    # 把两个Queue都注册到网络上，callable参数关联了Queue对象：
    QueueManager.register('task_queue',callable=return_task_queue)
    QueueManager.register('result_queue',callable=return_result_queue)
    QueueManager.register('rtpstream_queue', callable=return_rtpstream_queue)
    manager = QueueManager(address=('127.0.0.1', 5002), authkey=b'abc')
    manager.start()
    tshark_q = manager.task_queue()
    rtpstream_q = manager.rtpstream_queue()
    tshark_result_q = manager.result_queue()
    def to_tshark_q(sfile):
        while True:
            statinfo1 = os.stat(sfile)
            time.sleep(0.5)
            statinfo2 = os.stat(sfile)
            if statinfo1.st_size == statinfo2.st_size:
                tshark_q.put(sfile)  # 判断文件为目标文件后放入db_queue队列中，等待run函数获取后分析rtp流数据
                logger.debug('put tshark_q {0} and now the size is {1}'.format(sfile,tshark_q.qsize()))
                break
            else:
                pass

    def to_rtpstream_q(sfile):
        while True:
            statinfo1 = os.stat(sfile)
            time.sleep(1)
            statinfo2 = os.stat(sfile)
            if statinfo1.st_size == statinfo2.st_size:
                rtpstream_q.put(sfile)  # 判断文件为目标文件后放入rtp_stream队列中，等待run函数获取后插入数据库中
                logger.debug('put rtpstream_q {0} and now the size is {1}'.format(sfile,rtpstream_q.qsize()))
                break
            else:
                pass
            
    def scanrtp():
        ignlist_rtp = []
        while True:
            try:
                dt = datetime.datetime.now()
                dst = dt.strftime('%Y%m%d')
                source_dir_day_rtp = os.path.join(source_dir_rtp, dst)
                logger.debug('rtpstream_q size is {0}'.format(rtpstream_q.qsize()))
                for root, dirs, files in os.walk(source_dir_day_rtp):
                #for files in os.listdir(source_dir):
                    for fn in files:
                        #r = re.search("^dumpcap_\d{5}_(.*).pcap$", fn)
                        rtp = re.search("^rtpstream.*txt", fn)
                        if rtp is not None:
                            if fn not in ignlist_rtp:
                                ignlist_rtp.append(fn)
                                sfile = os.path.join(root, fn)  # sfile文件绝对路径
                                to_rtpstream_q(sfile)
                        else:
                            pass
                dst_s = dt.strftime('%H%M%S')
                if dst_s == "000000":#第二天清空ignlist，防止list过大
                    ignlist_rtp = []
            except Exception as e:
                logger.error(e)
            finally:
                time.sleep(1)

    def Scan():
        ignlist = []
        while True:
            try:
                dt = datetime.datetime.now()
                dst = dt.strftime('%Y%m%d')
                source_dir_day = os.path.join(source_dir, dst)
                logger.debug('tshark_q size is {0}'.format(tshark_q.qsize()))
                for root, dirs, files in os.walk(source_dir_day):
                #for files in os.listdir(source_dir):
                    for fn in files:
                        r = re.search("^dumpcap_\d{5}_(.*).pcap$", fn)
                        #rtp = re.search("^rtpstream.*txt", fn)
                        if r is not None:
                            if fn not in ignlist:
                                ignlist.append(fn)
                                sfile = os.path.join(root, fn)  # sfile文件绝对路径
                                to_tshark_q(sfile)
                        else:
                            pass
                dst_s = dt.strftime('%H%M%S')
                if dst_s == "000000":#第二天清空ignlist，防止list过大
                    ignlist = []
            except Exception as e:
                logger.error(e)
            finally:
                time.sleep(1)
    t1 = threading.Thread(target=scanrtp, name='LoopThread')
    t2 = threading.Thread(target=Scan, name='LoopThread')
    t1.start()
    t2.start()
