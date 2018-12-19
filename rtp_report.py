# -*- coding: utf-8  -*-
import configparser
import datetime
import re
import os, shutil, time
import logging
import multiprocessing
import threading
from multiprocessing.managers import BaseManager
from subprocess import Popen, PIPE
from t_db import oracledbproces
conf = configparser.ConfigParser()
conf.read("C:\\rtpstream\\conf.ini")
dbhost = conf.get("db", "dbhost")
port = int(conf.get("db", "port"))
dbname = conf.get("db", "dbname")
username = conf.get("db", "user")
password = conf.get("db", "password")

logger = logging.getLogger(__name__)#
logging.basicConfig(level=logging.DEBUG)
tshark_exe = conf.get("cmd", "tshark")
source_dir = conf.get("dir", "source_file_dir")
source_dir_rtp = conf.get("dir", "source_file_dir_rtp")
dt = datetime.datetime.now()
dst = dt.strftime('%Y%m%d')
dst_s = dt.strftime('%H%M%S')
rtpreport_dir = os.path.join(source_dir,dst)
rtpreport_dir_rtp = os.path.join(source_dir_rtp,dst)


#分布式进程
class QueueManager(BaseManager):
    pass
#task_queue = multiprocessing.Queue()
#rtpstream_q = multiprocessing.Queue()
#result_queue = multiprocessing.Queue()
QueueManager.register('task_queue')
QueueManager.register('rtpstream_queue')
QueueManager.register('result_queue')
manager = QueueManager(address=('127.0.0.1', 5002), authkey=b'abc')
manager.connect()
tshark_q=manager.task_queue()
rtpstream_q=manager.rtpstream_queue()
tshark_result_q=manager.result_queue()

def run():
    pcap_bak = conf.get("dir", "pcap_bak")
    #rtptxt = "rtpstream" + dst_s + ".txt"
    #rtpreport_dir_f = os.path.join(rtpreport_dir_rtp, rtptxt)
    #while tshark_q.qsize()>0:
    while True:
        try:
            dt = datetime.datetime.now()
            dst = dt.strftime('%Y%m%d')
            pcap_bak_dir = os.path.join(pcap_bak, dst)
            if not os.path.exists(pcap_bak_dir):
                os.makedirs(pcap_bak_dir)
            data = tshark_q.get()
            logger.info("get from tshark_q {0}".format(data))
            cmd = (r'{0} -r {1} -d udp.port==10000-65535,rtp -z rtp,streams'.format(tshark_exe, data))
            pcap_cmd = ("move /y {0} {1}".format(data, pcap_bak_dir))
            begin = datetime.datetime.now()
            a = Popen(cmd, stdout=PIPE, stderr=PIPE)
            stdout, stderr = a.communicate()
            stpstream = str(stdout)
            end = datetime.datetime.now()
            print("analysis {0} cost {1}".format(data, (end - begin)))
            print(pcap_cmd)
            b = Popen(pcap_cmd, stdout=PIPE, stderr=PIPE, shell=True)
            stdout, stderr = b.communicate()
            m = re.match(r".*(===== RTP Streams ======).*(Src IP addr  Port.*?)=*\\r\\n'$", stpstream)
            rtcp = m.group(2)
            a = rtcp.strip("\\r\\n").split("\\r\\n")
            a[0] = "SrcIp,SrcPort,DstIp,DstPort,SSRC,Payload,Pkts,Lost,LostRate,Max Delta(ms),Max Jitter(ms),Mean Jitter(ms),Problem"
            for i in range(len(a)):
                if i > 0:
                    a[i] = a[i].strip().split(" ")
                    a[i][1] = ' '.join(a[i][1:]).strip()
                    for j in range(15):  # 逐个字段截取，以“，”分割，生成csv格式
                        b = a[i][1].split(" ")
                        a[i][0] = a[i][0] + "," + b[0]
                        a[i][1] = ' '.join(b[1:]).strip()
                    a[i] = ''.join(a[i][0]).replace("ITU-T,G.711,PCMA", "ITU-T_G.711_PCMA").strip(",")
                else:
                    pass
            dst = data[-19:-5]
            file_id = data[-25:-20]
            if not os.path.exists(rtpreport_dir_rtp):
                os.makedirs(rtpreport_dir_rtp)
            rtptxt = "rtpstream" + file_id + ".txt"
            rtpreport_dir_f = os.path.join(rtpreport_dir_rtp, rtptxt)
            with open(rtpreport_dir_f, "a") as f:
                for i in range(len(a)):
                    if i > 0:
                        f.write(dst + "," + a[i] + "\n")
        except Exception as e:
            logger.error(e)


def ana2db():
    db = oracledbproces(dbhost, port, dbname, username, password)
    #logger.info("dbthread start")
    #rtpsql = 'insert into t_rtp_report(PCAP_TIME,SrcIp,SrcPort,DstIp,DstPort,SSRC,Payload,Pkts,Lost,LostRate,Max_Delta,Max_Jitter,Mean_Jitter,Problem) \
    #    values(:1,:2,:3,:4,:5,:6,:7,:8,:9,:10,:11,:12,:13,:14)'
    rtpsql = 'insert into t_rtp_report(PCAP_TIME,SrcIp,SrcPort,DstIp,DstPort,SSRC,Payload,Pkts,Lost,LostRate,Max_Delta,Max_Jitter,Mean_Jitter,Problem) \
        values(to_date(:1,\'YYYYMMDDHH24MISS\'),:2,:3,:4,:5,:6,:7,:8,:9,:10,:11,:12,:13,:14)'

    rtpsql_del = 'delete from t_rtp_report t where t.pcap_time<(sysdate-30/24/60)'#删除十分钟之前数据
    rtpsql_count = 'select count(1) from t_rtp_report'
    #source_dir_day = conf.get("test", "a")
    bak_dir = conf.get("dir", "bak_dir")
    sqllist = []
    while True:
        try:
            dt = datetime.datetime.now()
            dst = dt.strftime('%Y%m%d')
            bak_dir_day = os.path.join(bak_dir, dst)
            if not os.path.exists(bak_dir_day):
                os.makedirs(bak_dir_day)
            rtpfile = rtpstream_q.get()
            with open(rtpfile) as f:
                slist = f.read()
            dlist = slist.strip().split("\n")
            for i in dlist:
                a = i.split(",")
                b = tuple(a)
                sqllist.append(b)
            #print(sqllist)
            if db.dbexecmany(rtpsql, sqllist):
                sqllist = []
                #cmd = ("move /y {0} {1}".format(rtpfile, bak_dir_day))
                #print(cmd)
                #a = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
                #stdout, stderr = a.communicate()
                c = db.dbexec(rtpsql_count,None)
                print("after exec {0}".format(c))
                db.dbexec(rtpsql_del,None)
                logger.info("delete has executed")
                c = db.dbexec(rtpsql_count,None)
                print("after delete {0}".format(c))
                cmd = ("move /y {0} {1}".format(rtpfile, bak_dir_day))
                print(cmd)
                a = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
                stdout, stderr = a.communicate()
        except Exception as e:
            logger.error(e)

def start():
    t1 = threading.Thread(target=run, name='LoopThread')
    t2 = threading.Thread(target=ana2db, name='LoopThread')
    t1.start()
    t2.start()
if __name__ == "__main__":
    start()
