X Vulnerability Scanner Framework

多线程通用漏洞扫描框架。写该框架主要是为了加快POC编写速度，降低POC编写难度。项目目前初步开发阶段。目前已经支持漏洞拓展，支持多目标、多线程多漏洞扫描。针对通用系统类漏洞进行定时扫描或者应急扫描。

## 安装
python3 -m pip install -r requirements.txt

## 使用说明
```
python3 xscan.py -h

usage: xscan.py [-h] [-p POC] [-l POCLIST] [-i INPUT] [-o [OUTPUT]] [-n THREAD]

OPTIONS:
  -h, --help            show this help message and exit
  -p POC, --poc POC     payload name
  -l POCLIST, --poclist POCLIST
                        list payload
  -i INPUT, --input INPUT
                        targets,ip or host,ips,file,keywofd
  -o [OUTPUT], --output [OUTPUT]
                        save the result to text file
  -n THREAD, --thread THREAD
                        set thread numbers
```

-l 列出目前已经存在的poc列表

-p 为所使用的poc，未设置则默认为所有poc

-i 输入的目标，可以是单ip,多目标（IP，host，多个目标之间逗号分隔），文件读取。

-o 输出的内容，写入到的文件内容。

-n 线程数，默认是10线程。

## 漏洞示例
`git_config_infoleak.py`

```
import os,sys
import re
sys.path.append("../")
from lib.core import *


query = ""

class scannerclass(coreclass):
    name = "git信息泄漏漏洞"
    author = "BaCde"
    description = "git/config 信息泄漏，导致泄漏源代码"
    product = "homepage"
    homepage = ""
    Reference = ""
    vulid = ""
    pubdate = "2019.12.24"

    def __init__(self,target):
        coreclass.__init__(self,target)

    def scanner(self):
        payload = "/.git/config"
        url = self.url + payload
        #print(url)
        try:
            #auth = self.genauth("basic","admin","admin")
            #print(auth)
            r = self.get(url,self.headers,timeout=3)
            if r:
                content = r.content.decode()
                if self.matchexp(":",'[remote "origin"]',content):
                    ret = url
        except Exception as e:
            print(e)
        ret = self.output(payload,ret)
        return ret

if __name__ == "__main__":
   #可单独测试，方便漏洞调试。
   p = scannerclass("http://127.0.0.1:8080/")
   print(p.scanner())
```

pocs下有几个POC示例

## poc编写说明

**文件名命名规则**

产品名_版本号_漏洞路径_漏洞类型.py

例如：gitlab_all_index_fileanyread.py

**编写说明**

最上面的引用可以增加新的。不要删除，不要修改。

query = ""  该变量定义搜索语法，用于检索资产的方法（该代码未开放）

class scannerclass(coreclass):  #定义扫描类

里面定义一些scannerclass的属性，可设置的属性包括：

```
    name = ""    #漏洞名字
    author = "BaCde"   #作者
    description = "this is description"  #漏洞描述
    product = "homepage"    #产品名字
    homepage = ""    # 产品主页
    Reference = ""   #引用
    vulid = ""      #漏洞编号（cve、cnvd、cnnvd等）
    pubdate = "2019.12.24"    #漏洞发布日期
    headers = {}    #默认请求头
```

scanner函数为自己主要的扫描函数，这里是必须的。可以自己在文件中输出函数。这里写发包方法和判断漏洞逻辑。

coreclass相关内容

ua 属性，这里可以直接设置ua内容，如pc，chrome，也可以设置随机的。使用时直接采用ua.random()这种方式即可。ua的列表如下：

* random
* pc
* wap
* pc_linux
* pc_windows
* pc_mac
* internet_explorer
* chrome_pc
* chrome_pc_linux
* chrome_pc_mac
* chrome_pc_windows
* firefox_pc
* firefox_pc_linux
* firefox_pc_mac
* firefox_pc_windows
* android
* iphone
* chrome_wap
* chrome_wap_android
* wechat
* wechat_android
* wechat_iphone
* uc_browser_android
* baidu_box_app
* baidu_box_app_android
* baidu_box_app_iphone
* custom

方法如下：

1. setheader(key,value)

   设置请求头的内容.可以设置随机ua，如setheader("user-agent","random")

2. output(payload,result)

   结果输出格式化

3. genauth(authtype="",user="",pwd="")

   设置http请求验证，authtype包含basic和digest。

4. matchexp(opera,value,content)

   响应内容匹配函数，支持大于、小于、等于、包含、正则表达式、开头字符、结尾字符


   opera 值如下：
   ```
   re      正则
   ==      等于
   :       包含
   start   开始字符
   end     结束字符
   >       大于
   <       小于
   >=      大于等于
   <=      小于等于
   !=      不等于
   ```

5. get(self,url,headers,auth={},allow_redirect=True,timeout=10)

   get请求方法

6. post(self,url,headers,data,auth={},allow_redirect=True,timeout=10)

   post请求方法

7. put(self,url,headers,data,auth={},allow_redirect=True,timeout=10)

   put请求方法

8. option(self,url,headers,auth={},allow_redirect=True,timeout=10)

   option请求方法

## TODO
   1. SQL注入

   2. XSS检测

   3. DNSLOG\HTTPLOG平台,即对不回显情况支持

   4. 针对延时型的支持

   5. 修改类，返回响应时间、长度、内容、header、状态码等。

   6. tcp发包支持

   7. …………

注：请不要将该脚本用于非法用途，仅用于合法的，经过授权的渗透测试，公司内部安全检查与研究使用。由于使用工具带来的不良后果与本人无关。
