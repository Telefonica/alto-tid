#!/usr/bin/env python3

#import threading
import flask
from werkzeug.serving import make_server

ERRORES = { "sintax" : "E_SYNTAX", "campo" : "E_MISSING_FIELD", "tipo" : "E_INVALID_FIELD_TYPE", "valor" : "E_INVALID_FIELD_VALUE" }

#class AltoHttp(threading.Thread):
class AltoHttp():

    def __init__(self, a, ip="127.0.0.1", port=5000):
        #threading.Thread.__init__(self)
        self.app = flask.Flask("http")
        self.app.config["DEBUG"] = True
        self.alto = a
        self.port = port
        self.ip = ip
        self.app.route('/', methods=['GET'])(self.home)
        self.app.route('/directory', methods=['GET'])(self.api_directory)        
        self.app.route('/networkmap', methods=['GET','POST'])(self.api_pids)
        self.app.route('/costmap', methods=['GET','POST'])(self.api_costs)
        self.app.route('/maps', methods=['GET','POST'])(self.api_maps)       
        self.app.route('/endpoints/<string:pid>', methods=['GET'])(self.api_endpoint_costs)
        self.app.route('/properties/<string:pid>', methods=['POST','GET'])(self.api_properties)
        self.app.route('/qkd-properties/<string:pid>', methods=['GET'])(self.api_qkd_properties)
        self.app.route('/all/<string:a>/<string:b>', methods=['GET'])(self.api_all)
        self.app.route('/best/<string:a>/<string:b>', methods=['GET'])(self.api_shortest)
        self.app.route('/costmap/filter/<string:pid>', methods=['GET'])(self.api_costs_by_pid)
        self.app.route('/energy/<string:ipo>/<string:ipd>/<string:bits>', methods=['GET'])(self.energy_costs)
        self.server = None

    def run(self):
        #self.app.run(host="127.0.0.1", port=5000)
        self.server = make_server(self.ip, self.port, self.app)
        #self.server = make_server('192.168.165.193', 8080, self.app)
        print("API running on " + "\x1b[1;34m" +"http://127.0.0.1:5000" + "\x1b[1;37;40m")
        self.server.serve_forever()

    def detener(self):
        self.server.shutdown()

    #@self.app.route('/', methods=['GET'])
    def home(self):
        '''
            <h1>ALTO PoC's API</h1>
            <h2>Services expossed:</h2>
            <p><ul>
            <li>PIDs map: /networkmap </li>            
            <li>Costs map: /costmap </li>
            <li>Both maps: /maps </li>
            <li>Endpoint Costs: /endpoints/&ltstring:pid&gt </li>
            <li>Endpoints Properties: /properties/&ltstring:pid&gt </li>
            <li>Endpoints QKD Properties: /qkd-properties/&ltstring:pid&gt </li>
            <li>All disjunts paths between A & B: <b><tt> /all/&ltstring:a&gt/&ltstring:b&gt </b></tt></li>
            <li>Shortest path between A & B: <b><tt> /best/&ltstring:a&gt/&ltstring:b&gt </b></tt></li>
            <li>Filtered Cost map: /costmap/filter/&ltstring:pid&gt </li>
            </ul></p>
        '''
        return '''
            ALTO PoC's API
            Services expossed:
            1.  PIDs map: /networkmap ['GET']
            1'. NRP PIDs map: /networkmap ['POST']
            2.  Costs map: /costmap ['GET']
            2'. NRP Costs map: /costmap ['POST']
            3.  Both maps: /maps ['GET']
            3'. NRP Both maps: /maps ['POST']
            4.  Endpoint Costs: /endpoints/<string:pid>
            5.  Endpoints Properties: /properties/<string:pid> 
            6.  Endpoints QKD Properties: /qkd-properties/<string:pid>
            7.  QKD Properties type: /qkd-properties/yang
            8.  All disjunts paths between A & B: /all/<string:a>/<string:b>
            9.  Shortest path between A & B: /best/<string:a>/<string:b>
            10. Filtered Cost map: /costmap/filter/&ltstring:pid&gt </li>
        '''

    ###################################
    ##                               ##
    #   Services defined in RFC 7285  #
    ##                               ##
    ###################################

    # Map-Filteriong Service
    #@self.app.route('/costmap/filter/<string:pid>', methods=['GET'])
    def api_costs_by_pid(self, pid):
        if pid == None:
            return flask.jsonify({"ERROR" : ERRORES["valor"], "syntax-error": "PID not found."})
        if type(pid) is not str:
            return flask.jsonify({"ERROR" : ERRORES["tipo"], "syntax-error": "The PID type is incorrect. We need a string."})
        pid = self.sanitize_input_GET(pid)
        return flask.jsonify(self.alto.get_costs_map_by_pid(pid))
    
    #Endpoint Cost Service
    #@self.app.route('/costmap/<string:pid>', methods=['GET'])
    def api_endpoint_costs(self, pid):
        if pid == None:
            return flask.jsonify({"ERROR" : ERRORES["valor"], "syntax-error": "PID not found."})
        if type(pid) is not str:
            return flask.jsonify({"ERROR" : ERRORES["tipo"], "syntax-error": "The PID type is incorrect. We need a string."})        
        pid = self.sanitize_input_GET(pid)
        return flask.jsonify(self.alto.get_endpoint_costs(pid))
    
    #Map Service
    #@self.app.route('/maps', methods=['GET','POST'])
    def api_maps(self):
        if flask.request.method == 'POST':
            data = flask.request.json
            filter = data.get('filter',"")
            if filter == "":
                return flask.jsonify({"ERROR" : ERRORES["campo"], "syntax-error": "Properties field missing."})
            #print(filter)
            #filter = self.sanitize_input_POST(filter)
            return flask.jsonify(self.alto.get_maps(filter))
        return flask.jsonify(self.alto.get_maps())
    
    #Network Map service
    #@self.app.route('/costmap', methods=['GET','POST'])
    def api_costs(self):
        if flask.request.method == 'POST':
            data = flask.request.json
            filter = data.get('filter',"")
            if filter == "":
                return flask.jsonify({"ERROR" : ERRORES["campo"], "syntax-error": "Properties field missing."})                
            filter = self.sanitize_input_POST(filter)
            return flask.jsonify(self.alto.get_maps(filter))
        return flask.jsonify(self.alto.get_costs_map())
    
    #@self.app.route('/networkmap', methods=['GET','POST'])
    def api_pids(self):
        if flask.request.method == 'POST':
            data = flask.request.json
            filter = data.get('filter',"")
            filter = self.sanitize_input_POST(filter)
            return flask.jsonify(self.alto.get_maps(filter))
        return flask.jsonify(self.alto.get_net_map())
        #return flask.jsonify(self.alto.get_pids())
    
    #@self.app.route('/directory', methods=['GET'])
    def api_directory(self):
        return flask.jsonify(self.alto.get_directory())
    
        #@self.app.route('/properties/<string:pid>', methods=['POST'])
    def api_properties(self,pid):
        if pid == None:
            return flask.jsonify({"ERROR" : ERRORES["valor"], "syntax-error": "PID not found."})
        if type(pid) is not str:
            return flask.jsonify({"ERROR" : ERRORES["tipo"], "syntax-error": "The PID type is incorrect. We need a string."})
        if flask.request.method == 'POST':
            data = flask.request.json
            properties = data.get('properties',[])
            if properties == []:
                return flask.jsonify({"ERROR" : ERRORES["campo"], "syntax-error": "Properties field missing."})
            properties=self.sanitize_input_POST(properties)
            pid = data.get('pid',"")
            if pid == "":
                return flask.jsonify({"ERROR" : ERRORES["campo"], "syntax-error": "PID field missing."})
            if type(pid) is not str:
                return flask.jsonify({"ERROR" : ERRORES["tipo"], "syntax-error": "The PID type is incorrect. We need a string."})
            print(properties)
            return flask.jsonify(self.alto.get_properties(pid,properties))
        else:
            return flask.jsonify({"ERROR" : ERRORES["sintax"], "syntax-error": "Method not valid. Required a POST request."})            

    # #Endpoint Property Service
    # #@self.app.route('/properties/<string:pid>', methods=['GET'])
    # def api_properties(self, pid):
    #     return flask.jsonify(self.alto.get_properties(pid))    
    
    
    
    ###################################
    ##                               ##
    #           Ampliations           #
    ##                               ##
    ###################################
    
    
    #@self.app.route('/qkd-properties/<string:pid>', methods=['GET'])
    def api_qkd_properties(self,pid):
        if pid == None:
            return flask.jsonify({"ERROR" : ERRORES["valor"], "syntax-error": "PID not found."})
        if type(pid) is not str:
            return flask.jsonify({"ERROR" : ERRORES["tipo"], "syntax-error": "The PID type is incorrect. We need a string."})
        return flask.jsonify(self.alto.get_qkd_properties(pid))
    
    #All possible paths between A and B without any common node
    #@self.app.route('/all/<string:a>/<string:b>', methods=['GET'])
    def api_all(self, a,b):
        a = self.sanitize_input_GET(a)
        b = self.sanitize_input_GET(b)
        if (a == None) or (b == None):
            return flask.jsonify({"ERROR" : ERRORES["valor"], "syntax-error": "Two PIDs are needed."})
        if (type(a) is not str) or (type(b) is not str):
            return flask.jsonify({"ERROR" : ERRORES["tipo"], "syntax-error": "The PID type is incorrect. We need two strings."})
        #return flask.jsonify(str(self.alto.all_maps(self.alto.get_topology(), a, b)))
        return flask.jsonify(self.alto.parseo_yang(str(self.alto.all_maps(self.alto.get_topology(), a, b)),"all-paths"))
    
    #Best path between A and B
    #@self.app.route('/best/<string:a>/<string:b>', methods=['GET'])
    def api_shortest(self, a,b):
        a = self.sanitize_input_GET(a)
        b = self.sanitize_input_GET(b)
        if (a == None) or (b == None):
            return flask.jsonify({"ERROR" : ERRORES["valor"], "syntax-error": "Two PIDs are needed."})
        if (type(a) is not str) or (type(b) is not str):
            return flask.jsonify({"ERROR" : ERRORES["tipo"], "syntax-error": "The PID type is incorrect. We need two strings."})
        return flask.jsonify(str(self.alto.shortest_path(a, b)))

    # Map-Filteriong Service
    
    #@self.app.route('/energy/<string:ipo>/<string:ipd>/<string:bits>', methods=['GET'])
    def energy_costs(self, ipo, ipd, bits):
        valor = self.alto.get_energy(ipo, ipd, bits)
        respuesta = '{"watts-per-gb":' + str(valor) + "}"
        return flask.jsonify(respuesta)


    def sanitize_input_POST(texto):
        '''
        Characters acepted in the input: a-zA-Z0-9.{}[]",: -
        '''
        texto_sano = str(texto).replace('#', '').replace('--', '').replace("'", "").replace("//","").replace('_','').replace('<','').replace('>','').replace('&','').replace('%','')
        return texto_sano
    
    def sanitize_input_GET(texto):
        '''
        Characters acepted in the input: a-zA-Z0-9.:
        '''
        texto_sano = str(texto).replace('#', '').replace('--', '').replace("'", "").replace("//","").replace('_','').replace('<','').replace('>','').replace('&','').replace('%','').replace("{",'').replace("}","").replace('"',"").replace("-","")
        return texto_sano