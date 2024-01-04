#!/usr/bin/env python3

#import threading
import flask
from werkzeug.serving import make_server

#class AltoHttp(threading.Thread):
class AltoHttp():

    def __init__(self, a, port=5000):
        #threading.Thread.__init__(self)
        self.app = flask.Flask("http")
        self.app.config["DEBUG"] = True
        self.alto = a
        self.port = port
        self.app.route('/', methods=['GET'])(self.home)
        self.app.route('/costmap/filter/<string:pid>', methods=['GET'])(self.api_costs_by_pid)
        self.app.route('/properties/<string:pid>', methods=['POST','GET'])(self.api_properties)
        self.app.route('/costmap/<string:pid>', methods=['GET'])(self.api_endpoint_costs)
        self.app.route('/maps', methods=['GET'])(self.api_maps)
        self.app.route('/costmap', methods=['GET'])(self.api_costs)
        self.app.route('/networkmap', methods=['GET'])(self.api_pids)
        self.app.route('/directory', methods=['GET'])(self.api_directory)
        self.app.route('/all/<string:a>/<string:b>', methods=['GET'])(self.api_all)
        self.app.route('/best/<string:a>/<string:b>', methods=['GET'])(self.api_shortest)
        self.app.route('/graphs/all', methods=['POST'])(self.api_graphs)
        self.server = None

    def run(self):
        #self.app.run(host="127.0.0.1", port=5000)
        self.server = make_server('0.0.0.0', self.port, self.app)
        #self.server = make_server('192.168.165.193', 8080, self.app)
        print("API running on " + "\x1b[1;34m" +"http://127.0.0.1:5001" + "\x1b[1;37;40m")
        self.server.serve_forever()

    def detener(self):
        self.server.shutdown()

    #@self.app.route('/', methods=['GET'])
    def home(self):
        return '''
            <h1>ALTO PoC's API</h1>
            <h2>Services expossed:</h2>
            <p><ul>
            <li>All disjunts paths between A & B: <b><tt> /all/&ltstring:a&gt/&ltstring:b&gt </b></tt></li>
            <li>Shortest path between A & B: <b><tt> /best/&ltstring:a&gt/&ltstring:b&gt </b></tt></li>
            <li>Costs map: /costmap </li>
            <li>PIDs map: /networkmap </li>
            <li>Filtered Cost map: /costmap/filter/<string:pid></li>
            </ul></p>
        '''

    ###################################
    ##                               ##
    #   Services defined in RFC 7285  #
    ##                               ##
    ###################################

    # Map-Filteriong Service
    #@self.app.route('/costmap/filter/<string:pid>', methods=['GET'])
    def api_costs_by_pid(self, pid):
        return flask.jsonify(self.alto.get_costs_map_by_pid(pid))

    # #Endpoint Property Service
    # #@self.app.route('/properties/<string:pid>', methods=['GET'])
    # def api_properties(self, pid):
    #     return flask.jsonify(self.alto.get_properties(pid))
    
    #Endpoint Cost Service
    #@self.app.route('/costmap/<string:pid>', methods=['GET'])
    def api_endpoint_costs(self, pid):
        return flask.jsonify(self.alto.get_endpoint_costs(pid))
    
    #Map Service
    #@self.app.route('/maps', methods=['GET'])
    def api_maps(self):
        return flask.jsonify(self.alto.get_maps())
    
    #Network Map service
    #@self.app.route('/costmap', methods=['GET'])
    def api_costs(self):
        return flask.jsonify(self.alto.get_costs_map())
    
    #@self.app.route('/networkmap', methods=['GET'])
    def api_pids(self):
        return flask.jsonify(self.alto.get_net_map())
        #return flask.jsonify(self.alto.get_pids())
    
    #@self.app.route('/directory', methods=['GET'])
    def api_directory(self):
        return flask.jsonify(self.alto.get_directory())
    
        #@self.app.route('/properties/<string:pid>', methods=['POST'])
    def api_properties(self,pid):
        if flask.request.method == 'POST':
            data = flask.request.json
            properties = data.get('properties',[])
            print(properties)
        return flask.jsonify(self.alto.get_properties(pid,properties))

    
    
    
    
    ###################################
    ##                               ##
    #           Ampliations           #
    ##                               ##
    ###################################
    
    
    
    
    
    #All possible paths between A and B without any common node
    #@self.app.route('/all/<string:a>/<string:b>', methods=['GET'])
    def api_all(self, a,b):
        return flask.jsonify(self.alto.parseo_yang(str(self.alto.all_maps(self.alto.get_topology(), a, b)),"all-paths"))
    
    #Best path between A and B
    #@self.app.route('/best/<string:a>/<string:b>', methods=['GET'])
    def api_shortest(self, a,b):
        return flask.jsonify(str(self.alto.shortest_path(a, b)))
    

    ### Desire6G ampliation
    #@self.app.route('/graphs/all', methods=['POST'])(self.api_graphs)
    def api_graphs(self):
        if flask.request.method == 'POST':
            data = flask.request.json
            return flask.jsonify(str(self.alto.desire6g_graphs(data)))
        else:
            return "{'error':'method not valid.'}"

if __name__ == '__main__':
    #Creation of ALTO modules
    '''modules={}
    modules['bgp'] = TopologyBGP(('localhost',8888))
    #modules['ietf'] = TopologyIetf(('localhost',8081))
    alto = TopologyCreator(modules, 0)
    hilos = alto.lanzadera()

    hilo = HiloHTTP()
    hilo.start()
    hilos.append(hilo)
    sleep(30)
    alto.get_costs_map()
    '''    
    #speaker_bgp = ManageBGPSpeaker()
    #exabgp_process = speaker_bgp.check_tcp_connection()
    #alto = TopologyCreator(exabgp_process,0)
    #hilo = HiloHTTP()
    #hilo.start()
    #app.run(host='192.168.165.193', port=8080)
    #app.run()