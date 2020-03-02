#!python3
# Author       : BaCde

import elasticsearch
import pytz
import datetime
import time
import traceback
import sys
sys.path.append("../")
from config import *

es = elasticsearch.Elasticsearch(ES_HOST)

def search(body):
    res = es.search( index="spacex", body=body)
    return res
    
def convertrule(content,offset=0,size=500):
    content = content.strip()
    content = content.replace("\\",'\\\\')
    content = content.replace('"','\\\"')
    content = content.replace("'",'\\\"')
    ret = '{"query":{"bool":{"must":{"query_string":{"query":"%s"}}}}}' % content
    return ret
