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

def elastic_search(body):
    results = {}
    query = convertrule(body,0,50)
    res = es.search( index="spacex", body=query)
    if res:
        try:
            total = res["hits"]["total"]
        except KeyError :
            total = res["hits"]["total"]["value"]
        except Exception as e:
            total = 0
        results["total"] = total
        try: 
            results["hits"] = res["hits"]["hits"]
            if total > 50:
                for i in range(1,int(total / 50) + 1):
                    query = convertrule(body,i*50, 50)
                    res = es.search( index="spacex", body=query)

                    if res:
                        results["hits"].extend( res["hits"]["hits"])
        except Exception as e:
            print(str(e))
    return results
    
def convertrule(content,offset=0,size=500):
    content = content.strip()
    content = content.replace("\\",'\\\\')
    content = content.replace('"','\\\"')
    content = content.replace("'",'\\\"')
    ret = '{"query":{"bool":{"must":{"query_string":{"query":"%s"}}}},"from":%d,"size":%d,"sort":[],"aggs":{}}' % (content,offset,size)
    return ret
