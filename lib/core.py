#!python3
#-*- coding:utf8 -*-
import requests
import os
import re
from requests.auth import HTTPDigestAuth,HTTPBasicAuth

try:
    from lib.useragent import *
except:
    from useragent import *

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class coreclass(object):
    name = ""
    author = "BaCde"
    description = "this is description"
    product = "homepage"
    homepage = ""
    Reference = ""
    query = ""
    vulid = ""
    pubdate = "2019.12.24"
    host = ""
    portocol = ""
    port = 80
    request = requests.session()
    ua = useragent()
    headers = {}

    def __init__(self,target):
        self.target = target
        self.parsetarget()
        self.url = self.__weburl()
        self.auth = {}

    def setheader(self,key,value):
        if key.lower() == "user-agent" :
            if value =="random":
                self.headers[key] = self.ua.random()
        else:
            self.headers[key] = value

    #解析目标，分解协议，host，端口。
    def parsetarget(self):
        target = self.target
        if "://" not in target:
            self.portocol = "http"
            if ":" not in target:
                self.host = target
                self.port = 80
            else:
                self.host,self.port = target.split(":")
        else:
            regex = re.compile("(.{2,6})://(.+?):(\d{0,5})")
            match = regex.match(target)
            if match:
                self.portocol = match[1]
                self.host = match[2]
                try:
                    self.port = match[3]
                except Exception as e:
                    if self.portocol=="https":
                        self.port = 443
                    else:
                        self.port = 80
                    #print(e)

    def __weburl(self):
        return "{0}://{1}:{2}".format(self.portocol,self.host,self.port)

    def __auth(self):
        try:
            if self.auth["type"]=="basic":
                return HTTPBasicAuth(self.auth["user"],self.auth["pwd"])
            elif self.auth["type"]=="digest":
                return HTTPDigestAuth(self.auth["user"],self.auth["pwd"])
            else:
                return ""
        except Exception as e:
            print(e)

    def output(self,payload,result):
        return {"vulname":self.name,"payload":payload,"result":result,"query":self.query,"url":self.url}

    def genauth(self,authtype="",user="",pwd=""):
        self.auth["type"] = authtype
        self.auth["user"] = user
        self.auth["pwd"]  = pwd
        return self.auth

    def get(self,url,headers,auth={},allow_redirect=True,timeout=10):
        request = self.request
        ret = None
        if self.auth:
            try:
                ret = self.request.get(url=url,headers=headers,auth=self.__auth(),allow_redirects=allow_redirect,timeout=timeout,verify=False)
            except Exception as e:
                #print("get error:",str(e))
                pass
        else:
            try:
                ret = self.request.get(url=url,headers=headers,allow_redirects=allow_redirect,timeout=timeout,verify=False)
            except Exception as e:
                #print("get error:",str(e))
                pass
        return ret

    def post(self,url,headers,data,auth={},allow_redirect=True,timeout=10):
        ret = None
        if self.auth:
            try:
                ret = self.request.post(ur=url,headers=headers,data=data,auth=self.__auth(),allow_redirects=allow_redirect,timeout=timeout,verify=False)
            except Exception as e:
                print("get error:",str(e))
                pass
        else:
            try:
                ret = self.request.post(url=url,headers=headers,data=data,allow_redirects=allow_redirect,timeout=timeout,verify=False)
            except Exception as e:
                print("get error:",str(e))
        return ret

    def put(self,url,headers,data,auth={},allow_redirect=True,timeout=10):
        ret = None
        if self.auth:
            try:
                ret = self.request.get(ur=url,headers=headers,data=data,auth=self.__auth(),allow_redirects=allow_redirect,timeout=timeout,verify=False)
            except Exception as e:
                print("get error:",str(e))
                pass
        else:
            try:
                ret = self.request.get(url=url,headers=headers,data=data,allow_redirects=allow_redirect,timeout=timeout,verify=False)
            except Exception as e:
                print("get error:",str(e))
        return ret

    def option(self,url,headers,auth={},allow_redirect=True,timeout=10):
        ret = None
        if self.auth:
            try:
                ret = self.request.get(ur=url,headers=headers,auth=self.__auth(),allow_redirects=allow_redirect,timeout=timeout,verify=False)
            except Exception as e:
                print("get error:",str(e))
                pass
        else:
            try:
                ret = self.request.get(url=url,headers=headers,allow_redirects=allow_redirect,timeout=timeout,verify=False)
            except Exception as e:
                print("get error:",str(e))
        return ret

    def matchexp(self,opera,value,content):
        if opera == "re":
            match = None
            try:
                regex = re.compile(str(value),re.I,re.M,re.DOTALL)
                match = regex.match(str(content))
            except:
                pass
            return match
        elif opera == "==":
            return str(value) == str(content)
        elif opera == ":":
            return str(value) in str(content)
        elif opera == "start":
            return content.startswith(value)
        elif opera == "end":
            return content.endswith(value)
        elif opera == ">":
            try:
                return int(value) > int(content)
            except:
                return False
        elif opera =="<" :
            try:
                return int(value) < int(content)
            except:
                return False
        elif opera ==">=" :
            try:
                return int(value) < int(content)
            except:
                return False
        elif opera =="<=" :
            try:
                return int(value) < int(content)
            except:
                return False
        elif opera == "!=":
            return value !=content