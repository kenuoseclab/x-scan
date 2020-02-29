import os,sys
import re
sys.path.append("../")
from lib.core import *


query = ""

class scannerclass(coreclass):
    name = "SVN信息泄漏漏洞"
    author = "BaCde"
    description = ".svn/entries 信息泄漏，导致泄漏源代码"
    product = "homepage"
    homepage = ""
    Reference = ""
    vulid = ""
    pubdate = "2020.02.10"

    def __init__(self,target):
        coreclass.__init__(self,target)

    def scanner(self):
        payload = "/.svn/entries"
        url = self.url + payload
        #print(url)
        try:
            #auth = self.genauth("basic","admin","admin")
            #print(auth)
            r = self.get(url,self.headers,timeout=3)
            if r:
                content = r.content.decode()
                if self.matchexp(":",'svn:',content):
                    ret = url
        except Exception as e:
            print(e)
        ret = self.output(payload,ret)
        return ret
