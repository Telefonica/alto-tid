#from prometheus_api_client import PrometheusConnect
from time import sleep
import json
from modulos.alto_module import AltoModule
import requests


class TopologyPrometheus(AltoModule):

    def __init__(self, metrics, ip="0.0.0.0", port="80"):
        self.url_pmth = "http://"+ str(ip) + ":" + str(port)
        self.metrics = []
        for item in metrics:
            self.metrics.append(item)


    def get_metric_list(self):
        prometheus_url = self.url_pmth  + '/api/v1/label/__name__/values'
        response = requests.get(prometheus_url)
        data = response.json()
        metrics = []
        #datos = data["data"]
        for metrica in data["data"]:
            if metrica[0:3] == "net":
                metrics.append(metrica)
        print("Metricas:\t", metrics)
        return metrics


    def get_metric_value(self, metric_name):
        prometheus_url = self.url_pmth  + '/api/v1/query'
        query = f'query={metric_name}'
        response = requests.get(f'{prometheus_url}?{query}')
        data = response.json()
        #print("DATOS:\t", data)
        result = {}
        result['value'] = data['data']['result'][0]['value'][1]
        metric = metric_name.split("_")[:-1]
        result["metric"] = "_".join(metric)
        result["src"] = data['data']['result'][0]['metric']['source_node']
        result["dst"] = data['data']['result'][0]['metric']['target_node']
        #print("METRICA:\t", result)
        return result


    def guardar_metricas_json(metricas, archivo_salida):
        with open(archivo_salida, 'w') as f:
            json.dump(metricas, f, indent=4)

    def manage_topology_updates(self):
        while 1:
            metricas = self.get_metric_list()
            nodos = []
            links = []
            metrics = {}
            met_n = {"net_rtt_ms":"oLatencyNanos","net_throughput_kbps":"oBandWidthBits"}
            for met in metricas:
                valor = self.get_metric_value(met)
                if valor['src'] not in nodos.keys():
                    nodos[valor['src']]={"oNodeDegree":0, "oNodeThroughput":0}
                if valor['dst'] not in nodos:
                    nodos[valor['dst']]={"oNodeDegree":0, "oNodeThroughput":0}
                if (valor['src'],valor['dst']) not in links:
                    links.append((valor['src'],valor['dst']))
                    nodos[valor['dst']]["oNodeDegree"] = nodos[valor['dst']]["oNodeDegree"]+0.5
                    nodos[valor['src']]["oNodeDegree"] = nodos[valor['src']]["oNodeDegree"]+0.5
                if (valor['src'],valor['dst']) not in metrics.keys():
                    metrics[(valor['src'],valor['dst'])]={}
                    metrics[(valor['src'],valor['dst'])][valor["metric"]]=valor['value']
                else:
                    metrics[(valor['src'],valor['dst'])][valor["metric"]]=valor['value']
                if valor["metric"] == 'net_throughput_kbps':
                    nodos[valor['src']]["oNodeThroughput"]= nodos[valor['src']]["oNodeThroughput"] + int(valor['value'])/1e6
                elif valor["metric"] == 'net_rtt_ms':
                    metrics[(valor['src'],valor['dst'])][valor["metric"]] = str(metrics[(valor['src'],valor['dst'])][valor["metric"]])+"e6"


            print("NODOS:\t", nodos)
            print("ENLACES:\t",links)
            print("METRICAS:\t", metrics)

            print("Topology loaded")
            data = '{"pids":'+ '""' +',"nodes-list": '+ str(nodos.keys()) +',"costs-list": '+ str(metrics) +',"prefixes": '+ "" +"}"
            print(data)
            self.return_info(3,0,1, data)
            sleep(30)


if __name__ == "__main__":
    # Métricas que deseas recuperar
    metricas = [
        "node_name",
        "link_id",
        "link_failure",
        "packet_loss",
        "node_net_failure",
        "path_failure",
        "node_throughput",
        "ebw",
        "ibw",
        "zone",
        "node_degree",
        "latency",
        "path_length",
        "link_energy"
    ]
    values = [{'value': '0.311', 'metric': 'net_jitter_ms', 'src': 'netma-test-2', 'dst': 'netma-test-3'}, {'value': '2.003', 'metric': 'net_jitter_ms', 'src': 'netma-test-2', 'dst': 'netma-test-1'}, {'value': '0.097', 'metric': 'net_jitter_ms', 'src': 'netma-test-3', 'dst': 'netma-test-2'}, {'value': '0.397', 'metric': 'net_jitter_ms', 'src': 'netma-test-3', 'dst': 'netma-test-1'}, {'value': '0.201', 'metric': 'net_jitter_ms', 'src': 'netma-test-1', 'dst': 'netma-test-2'}, {'value': '0.223', 'metric': 'net_jitter_ms', 'src': 'netma-test-1', 'dst': 'netma-test-3'},{'value': '1.411', 'metric': 'net_rtt_ms', 'src': 'netma-test-2', 'dst': 'netma-test-3'}, {'value': '1.343', 'metric': 'net_rtt_ms', 'src': 'netma-test-2', 'dst': 'netma-test-1'}, {'value': '1.067', 'metric': 'net_rtt_ms', 'src': 'netma-test-3', 'dst': 'netma-test-2'}, {'value': '1.145', 'metric': 'net_rtt_ms', 'src': 'netma-test-3', 'dst': 'netma-test-1'},{'value': '1.445', 'metric': 'net_rtt_ms', 'src': 'netma-test-1', 'dst': 'netma-test-2'},{'value': '1.305', 'metric': 'net_rtt_ms', 'src': 'netma-test-1', 'dst': 'netma-test-3'}, {'value': '786006', 'metric': 'net_throughput_kbps', 'src': 'netma-test-2', 'dst': 'netma-test-3'}, {'value': '761528', 'metric': 'net_throughput_kbps', 'src': 'netma-test-2', 'dst': 'netma-test-1'}, {'value': '703681', 'metric': 'net_throughput_kbps', 'src': 'netma-test-3', 'dst': 'netma-test-2'}, {'value': '676144', 'metric': 'net_throughput_kbps', 'src': 'netma-test-3', 'dst': 'netma-test-1'}, {'value': '745310', 'metric': 'net_throughput_kbps', 'src': 'netma-test-1', 'dst': 'netma-test-2'}, {'value': '729834', 'metric': 'net_throughput_kbps', 'src': 'netma-test-1', 'dst': 'netma-test-3'}]
    nodos = {}
    links = []
    metrics = {}
    for valor in values:
        if valor['src'] not in nodos.keys():
            nodos[valor['src']]={"oNodeDegree":0, "oNodeThroughput":0}
        if valor['dst'] not in nodos:
            nodos[valor['dst']]={"oNodeDegree":0, "oNodeThroughput":0}
        if (valor['src'],valor['dst']) not in links:
            links.append((valor['src'],valor['dst']))
            nodos[valor['dst']]["oNodeDegree"] = nodos[valor['dst']]["oNodeDegree"]+0.5
            nodos[valor['src']]["oNodeDegree"] = nodos[valor['src']]["oNodeDegree"]+0.5
        if (valor['src'],valor['dst']) not in metrics.keys():
            metrics[(valor['src'],valor['dst'])]={}
            metrics[(valor['src'],valor['dst'])][valor["metric"]]=valor['value']
        else:
            metrics[(valor['src'],valor['dst'])][valor["metric"]]=valor['value']
        if valor["metric"] == 'net_throughput_kbps':
            nodos[valor['src']]["oNodeThroughput"]= nodos[valor['src']]["oNodeThroughput"] + int(valor['value'])/1e6
        elif valor["metric"] == 'net_rtt_ms':
            metrics[(valor['src'],valor['dst'])][valor["metric"]] = str(metrics[(valor['src'],valor['dst'])][valor["metric"]])+"e6"

    print("NODOS:\t", nodos)
    print("ENLACES:\t",links)
    print("METRICAS:\t", metrics)



    #metricas2 = ["net_jitter_ms","net_rtt_ms","net_throughput_kbps"]
    #nem = Nemesys(metricas2, "10.96.181.243", "9090")
    ## Obtener métricas de Prometheus
    #metricas_obtenidas = obtener_metricas_prometheus(url_prometheus, metricas2)
    # Guardar las métricas en un archivo JSON
    #guardar_metricas_json(metricas_obtenidas, "metricas.json")

