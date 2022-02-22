#!/usr/local/bin/python3.8
from confluent_kafka import Consumer, KafkaException
import json
import time
from pymemcache.client.base import Client

# See https://github.com/edenhill/librdkafka/blob/master/CONFIGURATION.md
bootstrap_servers = "" #enter kafka host
group_id = "threatbusgoesbrrr"
topics = ["url","domain","hostname","sha1","sha256","ip-dst","md5"]
clientHashes = Client(('127.0.0.1', 11211)) #1st memcached instance 
clientBasicNetwork = Client(('127.0.0.1', 11212))#2nd
clientOthers = Client(('127.0.0.1', 11213))#3rd
def receive():
    conf = {
        "bootstrap.servers": bootstrap_servers,
        "group.id": group_id,
        "enable.auto.commit":"false",
        "auto.offset.reset": "earliest",
    }
    consumer = Consumer(conf)
    consumer.subscribe(topics)
    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            yield (msg)
    except KeyboardInterrupt:
        pass

    finally:
        consumer.close()


if __name__ == "__main__":
    counter=0
    start_time = time.time()
    for msg in receive():
        if msg.error():
            print(f"error: {KafkaException(msg.error())}")
        else:
            #print(f"topic: {msg.topic()}, message: {msg.value().decode('utf8')}")
            new_message=msg.value().decode('utf8')
            new_message=new_message.replace('\'','\"')
            #new_message=new_message.replace('\'','')
            new_message=new_message.replace('None','"None"')
            #print(f"topic: {msg.topic()}, message: {json.loads(json.dumps(new_message))}")
            #print(type(new_message))
            try:
                IOC_message=json.loads(new_message)
            except Exception as Error:
                print(Error)
                pass
            if IOC_message['type'] in ('sha256','sha1','md5'):
                try:
                    clientHashes.set(IOC_message['type'] + "-" + IOC_message['indicator'], IOC_message['content'], 0)
                    print(IOC_message['indicator'])
                    counter =  counter + 1
                except Exception as Error:
                    print(Error)
                    pass
            elif IOC_message['type'] in ('domain','ip-dst'):
                try:
                    clientBasicNetwork.set(IOC_message['type'] + "-" + IOC_message['indicator'], IOC_message['content'], 0)
                    print(IOC_message['indicator'])
                    counter =  counter + 1
                except Exception as Error:
                    print(Error)
                    pass
            else:
                try:
                    clientOthers.set(IOC_message['type'] + "-" + IOC_message['indicator'], IOC_message['content'], 0)
                    print(IOC_message['indicator'])
                    counter =  counter + 1
                except Exception as Error:
                    print(Error)
                    pass 

    print("--- %s seconds ---" % (time.time() - start_time))
    print("--- %s total attributes ---" % (counter))


