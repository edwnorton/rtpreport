# -*- coding: utf-8  -*-
import cx_Oracle
import configparser
import logging
import time, os, re, datetime
import multiprocessing
from subprocess import Popen,PIPE
conf = configparser.ConfigParser()
logging.basicConfig(level=logging.DEBUG)
conf.read("C:\\rtpstream\\conf.ini")
logger = logging.getLogger(__name__)
dbhost = conf.get("db", "dbhost")
port = int(conf.get("db", "port"))
dbname = conf.get("db", "dbname")
username = conf.get("db", "user")
password = conf.get("db", "password")

class oracledbproces():
    def __init__(self, dbhost, port, dbname, username, passwd):
        self.dbhost = dbhost
        self.port = port
        self.dbname = dbname
        self.username = username
        self.password = passwd
        self.connectstat = False
        self.connect()

    def connect(self):
        try:
            self.dsn = cx_Oracle.makedsn(self.dbhost, self.port, self.dbname)
            self.dbpool = cx_Oracle.SessionPool(user=self.username, password=self.password, dsn=self.dsn,
                                                min=1, max=50, increment=1)
            self.connectstat = True
            self._oraconn = self.dbpool.acquire()
            self._oraconn.autocommit = True
            self._cur = self._oraconn.cursor()
            logger.info('connect ok')
        except:
            self.connectstat = False
            logger.error('connect failed')

    def reconnect(self):
        try:
            self.dbpool.drop(self._oraconn)
            self._oraconn = self.dbpool.acquire()
            self._oraconn.autocommit = True
            self._cur = self._oraconn.cursor()
            self.connectstat = True
            logger.info('reconnect sucess')
        except:
            logger.error('reconnect failed ')

    def dbexec(self, commd, value):
        try:
            if value == None:
                self._cur.execute(commd)
                self._oraconn.commit()
            else:
                self._cur.execute(commd, value)
                self._oraconn.commit()
            if commd.strip().lower().startswith('select'):
                return self._cur.fetchall()
        except cx_Oracle.DatabaseError as exc:
            error, = exc.args
            if int(error.code) == 3114 or int(error.code) == 3113:
                while self.connectstat:
                    self.connectstat = False
                    logger.error('reconnect retry ')
                    self.reconnect()
                    if self.connectstat:
                        if value == None:
                            self._cur.execute(commd)
                            self._oraconn.commit()
                        else:
                            self._cur.execute(commd, value)
                            self._oraconn.commit()
                        return self._cur.fetchall()
                    time.sleep(3)
        except Exception as e:
            logger.error('commd:{0},[{1}]'.format(commd, e))
    def dbexecmany(self, sql, valuelist):
        try:
            self.valuelist = valuelist
            self._cur.prepare(sql)
            self._cur.executemany(sql, valuelist)
            self._oraconn.commit()
            #self._cur.close()
            logger.debug('inert urs_event count {0}'.format(len(self.valuelist)))
            return True
            #if commd.strip().lower().startswith('select'):
            #    return self._cur.fetchall()
        except cx_Oracle.DatabaseError as exc:
            error, = exc.args
            if int(error.code) == 3114 or int(error.code) == 3113:
                while self.connectstat:
                    self.connectstat = False
                    logger.error('reconnect retry ')
                    self.reconnect()
                    if self.connectstat:
                        self.valuelist = valuelist
                        self._cur.prepare(sql)
                        self._cur.executemany(sql, valuelist)
                        self._oraconn.commit()
                        return True
                    time.sleep(3)
        except Exception as e:
            logger.error(e)
            return False



if __name__ == "__main__":
    conf.read("C:\\rtpstream\\conf.ini")
    dbhost = conf.get("db", "dbhost")
    port = int(conf.get("db", "port"))
    dbname = conf.get("db", "dbname")
    username = conf.get("db", "user")
    password = conf.get("db", "password")
    db = oracledbproces(dbhost, port, dbname, username, password)
    #sqllist = []
    rtpsql = 'insert into t_rtp_report(PCAP_TIME,SrcIp,SrcPort,DstIp,DstPort,SSRC,Payload,Pkts,Lost,LostRate,Max_Delta,Max_Jitter,Mean_Jitter,Problem) \
            values(to_date(:1,\'YYYYMMDDHH24MISS\'),:2,:3,:4,:5,:6,:7,:8,:9,:10,:11,:12,:13,:14)'
    source_dir_day = conf.get("test", "a")
    bak_dir = conf.get("dir", "bak_dir")

    def run():
        sqllist = []
        while True:
            try:
                dt = datetime.datetime.now()
                dst = dt.strftime('%Y%m%d')
                bak_dir_day = os.path.join(bak_dir, dst)
                if not os.path.exists(bak_dir_day):
                    os.makedirs(bak_dir_day)
                for root, dirs, files in os.walk(source_dir_day):
                    for fn in files:
                        rtp = re.search("^rtpstream.*txt", fn)
                        if rtp is not None:
                            sfile = os.path.join(root, fn)  # sfile文件绝对路径
                            with open(sfile) as f:
                                slist = f.read()
                            dlist = slist.strip().split("\n")
                            for i in dlist:
                                a = i.split(",")
                                b = tuple(a)
                                sqllist.append(b)
                            #print(sqllist)
                            db.dbexecmany(rtpsql, sqllist)
                            sqllist = []
                            cmd = ("move {0} {1}".format(sfile, bak_dir_day))
                            print(cmd)
                            a = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
                            stdout, stderr = a.communicate()
                            #a.wait()
            except Exception as e:
                logger.error(e)

    run()
