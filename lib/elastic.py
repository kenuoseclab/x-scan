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

def search_all(index,body):
    global es
    results = {}
    query = convertrule(body,0,50)
    try:
        r = es.search(index=index,body=query,scroll='5m',size=500)
        #print(r)
        total=r["hits"]["total"]
        results["total"] = total
        results["hits"] = r['hits']['hits']
        scroll_id = r['_scroll_id']

        for i in range(1, int(total/500)+1):
            r = es.scroll(scroll_id=scroll_id,scroll='5m')['hits']['hits']
            results["hits"] += r
        es.clear_scroll(scroll_id=scroll_id)
    except Exception as e:
        traceback.print_exc()
    return results

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

print(search_all("spacex","protocol:http"))