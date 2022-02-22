# -*- coding: utf-8 -*-
import json
from confluent_kafka import Producer
import time
import os
from OTXv2 import OTXv2
from datetime import datetime, timedelta


proxy = 'set_proxy'

os.environ['http_proxy'] = proxy 
os.environ['HTTP_PROXY'] = proxy
os.environ['https_proxy'] = proxy
os.environ['HTTPS_PROXY'] = proxy
new_items=[]

path_to_file = "json_data.json"
bootstrap_servers = "enter_kafka_instance" # PLAINTEXT://
topic = "indicator"
producer = Producer({"bootstrap.servers": bootstrap_servers})

def saveTimestamp(timestamp=None):
        mtimestamp = timestamp
        if not timestamp:
                mtimestamp = datetime.now().isoformat()
        with open("/home/misp/test/timestamp", "w") as file:
            file.write(mtimestamp)

def readTimestamp():
        with open("/home/misp/test/timestamp", "r") as file:
            mtimestamp = file.read()
        return mtimestamp

 
def loadjson(path_to_file):
    with open(path_to_file,'r+') as file:
        data = json.load(file)
    return data


def getotxjson():
    mtimestamp = readTimestamp()
    otx_key = 'otx_key' #enter otx key
    otx = OTXv2(otx_key)
    pulses=otx.getsince(mtimestamp)
    return pulses

def openfilter():
    with open('path_to_whitelist.txt','r+') as filter:
        for line in filter:
            new_items.append(line.rstrip("\n"))
    return(new_items)


def parsejson(data):
    new_items=openfilter()
    counter=0
    for i in range(len(data)):
        counter = counter + len(data[i]['indicators'])
        for y in range(len(data[i]['indicators'])):
            data[i]['indicators'][y]['content'] = data[i]['name'] +'|'+ data[i]['description']
            if (data[i]['indicators'][y]['type']) in ('IPv6','IPv4'):
                data[i]['indicators'][y]['type'] = 'ip-dst'
                producer.produce('ip-dst', str(data[i]['indicators'][y]).encode('utf8'))
            elif((data[i]['indicators'][y]['type']) in ('hostname')):
                data[i]['indicators'][y]['type'] = 'hostname'
                producer.produce('hostname', str(data[i]['indicators'][y]).encode('utf8'))
            elif((data[i]['indicators'][y]['type']) in ('domain') and not ((data[i]['indicators'][y]['indicator']) in new_items)):
                data[i]['indicators'][y]['type'] = 'domain'
                if data[i]['indicators'][y]['indicator'] == 'facebook.com':
                    print(data[i]['indicators'][y]['indicator'])
                producer.produce('domain', str(data[i]['indicators'][y]).encode('utf8'))
            elif((data[i]['indicators'][y]['type']) in ('URI', 'URL')):
                data[i]['indicators'][y]['type'] = 'url'
                producer.produce('url', str(data[i]['indicators'][y]).encode('utf8'))
            elif((data[i]['indicators'][y]['type']) in ('FileHash-MD5')):
                data[i]['indicators'][y]['type'] = 'md5'
                producer.produce('md5', str(data[i]['indicators'][y]).encode('utf8'))
            elif((data[i]['indicators'][y]['type']) in ('FileHash-SHA1')):
                data[i]['indicators'][y]['type'] = 'sha1'
                producer.produce('sha1', str(data[i]['indicators'][y]).encode('utf8'))
            elif((data[i]['indicators'][y]['type']) in ('FileHash-SHA256')):
                data[i]['indicators'][y]['type'] = 'sha256'
                producer.produce('sha256', str(data[i]['indicators'][y]).encode('utf8'))
            else:
                producer.produce('indicator', str(data[i]['indicators'][y]).encode('utf8'))

    producer.flush(1)
    return counter



if __name__ == "__main__":

    start_time = time.time()
    data = getotxjson()
    print("--- %s total attributes ---" % parsejson(data) )
    print("--- %s seconds ---" % (time.time() - start_time))
    saveTimestamp()

    
