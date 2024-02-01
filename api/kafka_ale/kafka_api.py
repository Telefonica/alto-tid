#!/usr/bin/env python3
# © 2024 Telefónica Innovación Digital, All rights reserved


from kafka import KafkaProducer
from kafka import KafkaConsumer
import json
import os


class AltoProducer:

    def __init__(self, ip_k, port_k):
        #self.producer = KafkaProducer(bootstrap_servers=ip_k + ':' + port_k, value_serializer=lambda v: json.dumps(v).encode('utf-8'))
        self.producer = KafkaProducer(bootstrap_servers=ip_k + ':' + port_k)
        self.metrics = {}
        #print("Definición realizada")

    def envio_alto(self, topic, msg, debug):
        """ Realize the deliver and waits until the response comes.
        Sends msg to the topic queue of the server defined in the producer definition.
        """
        try:
            future = self.producer.send(topic, value=bytes(str(msg), 'utf-8'))
            #future = self.producer.send('alto-costes', b'PRUEBAfinal')
            result = future.get()
            if debug:
                print(result)
        except Exception as e:
            print(str(e))

    def get_metrics(self):
        """ Return the metrics to the API client.
        """
        self.metrics = self.producer.metrics()
        return self.metrics

    def envio_alto_archivo(self, topic, nfile, npath):
         """Writes the nfile content in the queue defined by the topic.
         """
         full_path = os.path.join(npath, nfile)
         try:
             #in_path = open(full_path, 'r')
             in_path = open('/root/cost_map.json', 'r')
             self.producer.send( topic, bytes(in_path.read(), 'utf-8') )
             return True
         except Exception as e:
             print(str(e))
             return False

    #Ampliable con serializaciones o con colas divididas en varios bloques.


class AltoConsumer:
    def __init__(self, ip_k, port_k, topic):
        comodin = ip_k + ":" + port_k
        self.consumer = KafkaConsumer(topic, bootstrap_servers=comodin)
        self.metrics = {}

    def recepcion_alto_total(self):
        """ Reads each msg received by the consumer and returns a list of msgs.
        """
        msgs = []
        for msg in self.consumer:
            msgs.append(msg)
        print(msgs)

    def recepcion_alto(self):
        """ Returns the first unreaded msg received by the consumer """
        return next(self.consumer)

    def get_metrics(self):
        """ Return the metrics to the API client.
        """
        self.metrics = self.consumer.metrics()
        return self.metrics

    #Ampliable con des-serializaciones o con distintos tipos de recepciones.


