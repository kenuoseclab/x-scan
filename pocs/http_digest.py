import os,sys
import re
sys.path.append("../")
from lib.core import *

query = ""

class scannerclass(coreclass):
    name = "http basic 弱密码爆破"
    author = "BaCde"
    description = "http basic 弱密码爆破"
    product = "homepage"
    homepage = ""
    Reference = ""
    vulid = ""
    pubdate = "2020.01.06"

    def __init__(self,target):
        coreclass.__init__(self,target)

    def scanner(self):
        ret = ""
        payload = "/"
        url = self.url + payload
        try:
            self.setheader("user-agent","random")
            r = self.get(url,self.headers,timeout=3)
            if r:
                if r.status_code == 401:
                    try:
                        auth = self.genauth("digest","admin","admin")
                        r2 = self.get(url,self.headers,timeout=3)
                        if r2.status_code ==200:
                            ret = auth
                    except Exception as e:
                        print(e)
        except Exception as e:
            print(e)
        if ret :
            ret = self.output(payload,ret)
            return ret

