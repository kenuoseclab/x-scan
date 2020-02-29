
#!python3
#-*- coding:utf8 -*-
import sys,os,time
import argparse
from lib import threadpool
if sys.version <= '2':
    reload(sys)
    sys.setdefaultencoding('utf8')
import requests
import re


TIMEOUT = 5
THREAD_COUNT = 50
TOO_LONG = 50 * 1024 * 1024

def banner():
    print("""
                __    __  _____   _____       ___   __   _  
                \ \  / / /  ___/ /  ___|     /   | |  \ | | 
                 \ \/ /  | |___  | |        / /| | |   \| | 
                  }  {   \___  \ | |       / / | | | |\   | 
                 / /\ \   ___| | | |___   / /  | | | | \  | 
                /_/  \_\ /_____/ \_____| /_/   |_| |_|  \_| 

                                            # Coded By BaCde
    """)


def parser_error(errmsg):
    #banner()
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    sys.exit()

def parse_args():
    parser = argparse.ArgumentParser(epilog="")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-p', '--poc', help="payload name", default="",required=False)
    parser.add_argument('-l', '--poclist', help="list payload", default=False,required=False)
    parser.add_argument('-i', '--input', help="targets,ip or host,ips,file", default="target.txt",required=False)
    parser.add_argument('-o', '--output', help='save the result to text file', nargs='?', default="result.txt",required=False)
    parser.add_argument('-n', '--thread', help='set thread numbers',default=10)
    return parser.parse_args()


def readfile(pfile):
    fp = open(pfile,"r")
    content = fp.read()
    fp.close()
    return content

def writefile(pfile,content):
    fp = open(pfile,"a")
    fp.write(str(content))
    fp.write("\n")
    fp.close()

"""
input 有3种情况：
1、单个目标
2、文件列表
3、多个目标
"""
def gettarget(input):
    targets = []
    if os.path.exists(input):  #输入的是否为文件
        targets = readfile(input).split("\n")
    elif "," in input:  #多目标
        targets = input.split(",")
    else:
        targets.append(input)   #单个目标
    return targets     #返回列表

#获取poc列表
def listpoc(flag=0):
    pocs = []
    n = 0
    exp = ".*?.py$"
    regex = re.compile(exp)
    try:
        for file in os.listdir("pocs"):
            if regex.search(file):
                pocs.append(file.replace(".py",""))
        if flag ==0:
            print("poc lists:\n")
            for poc in pocs:
                print(poc + "\n")
            print("poc tatal: %d " % len(pocs))
    except Exception as e:
        print("poc list load error.\t" + str(e))

    return pocs

def callback(status,result):
    global output
    if status:
        if result:
            print("result:",result)
            writefile("results/%s" % output,result)

if __name__ == "__main__":
    banner()
    args = parse_args()
    poc = args.poc
    #param = args.param
    input = args.input
    output = args.output
    l = args.poclist
    threadnum = int(args.thread)
    pool = threadpool.ThreadPool(threadnum)
    pocs = []
    if l :
        listpoc()
    else :
        if poc =="":
            poc = "all"
        if poc =="all":
            pocs = listpoc(1)
        else:
            if "," in poc:
                for p in poc.split(","):
                    p = p.strip()
                    if p not in pocs:
                        pocs.append(p) 
        for pocname in pocs:
            _temp = __import__("pocs."+pocname)
            f = getattr(_temp,pocname)

            targets = gettarget(input)
            #print(targets)
            for target in targets:
                target = target.strip()
                if target :
                    scan = f.scannerclass(target)
                    pool.run(scan.scanner, '',callback=callback)

    pool.close()