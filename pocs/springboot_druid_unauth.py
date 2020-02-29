import os,sys
import re
sys.path.append("../")
from lib.core import *

query = ""

class scannerclass(coreclass):
    name = "Druid 未授权访问"
    author = "BaCde"
    description = "SpringBoot Druid 未授权访问，导致敏感信息"
    product = "homepage"
    homepage = ""
    Reference = ""
    vulid = ""
    pubdate = "2020.02.11"

    def __init__(self,target):
        coreclass.__init__(self,target)

    def scanner(self):
        payload = "/druid/index.html"
        url = self.url + payload
        #print(url)
        try:
            r = self.get(url,self.headers,timeout=3)
            if r:
                content = r.content.decode()
                if self.matchexp(":",'Druid Stat Index',content):
                    ret = url
        except Exception as e:
            print(e)
        ret = self.output(payload,ret)
        return ret
