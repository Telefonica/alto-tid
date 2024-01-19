#!/usr/bin/env python3

#import threading
import flask
from werkzeug.serving import make_server

ERRORES = { "sintax" : "E_SYNTAX", "campo" : "E_MISSING_FIELD", "tipo" : "E_INVALID_FIELD_TYPE", "valor" : "E_INVALID_FIELD_VALUE" }

#class AltoHttp(threading.Thread):
class AltoHttp():

    def __init__(self, a, ip="0.0.0.0", port=5000):
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
        print("API running on " + "\x1b[1;34m" +"http://127.0.0.1:" + str(self.port) + "\x1b[1;37;40m")
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
            <li>Desire Graphs request: /graphs/all</li>
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
        if pid == None:
            return flask.jsonify({"ERROR" : ERRORES["valor"], "syntax-error": "PID not found."})
        if type(pid) is not str:
            return flask.jsonify({"ERROR" : ERRORES["tipo"], "syntax-error": "The PID type is incorrect. We need a string."})
        #pid = self.sanitize_input_GET(pid)
        return flask.jsonify(self.alto.get_costs_map_by_pid(pid))

    # #Endpoint Property Service
    # #@self.app.route('/properties/<string:pid>', methods=['GET'])
    # def api_properties(self, pid):
    #     return flask.jsonify(self.alto.get_properties(pid))
    
    #Endpoint Cost Service
    #@self.app.route('/costmap/<string:pid>', methods=['GET'])
    def api_endpoint_costs(self, pid):
        if pid == None:
            return flask.jsonify({"ERROR" : ERRORES["valor"], "syntax-error": "PID not found."})
        if type(pid) is not str:
            return flask.jsonify({"ERROR" : ERRORES["tipo"], "syntax-error": "The PID type is incorrect. We need a string."})        
        #pid = self.sanitize_input_GET(pid)
        return flask.jsonify(self.alto.get_endpoint_costs(pid))
    
    #Map Service
    #@self.app.route('/maps', methods=['GET','POST'])
    def api_maps(self):
        if flask.request.method == 'POST':
            data = flask.request.json
            filter = data.get('filter',"")
            if filter == "":
                return flask.jsonify({"ERROR" : ERRORES["campo"], "syntax-error": "Properties field missing."})
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
            #filter = self.sanitize_input_POST(filter)      
            return flask.jsonify(self.alto.get_maps(filter))
        return flask.jsonify(self.alto.get_costs_map())
    
    #@self.app.route('/networkmap', methods=['GET','POST'])
    def api_pids(self):
        if flask.request.method == 'POST':
            data = flask.request.json
            filter = data.get('filter',"")
            #filter = self.sanitize_input_POST(filter)
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
            #properties=self.sanitize_input_POST(properties)
            print(properties)
            return flask.jsonify(self.alto.get_properties(pid,properties))
        else:
            return flask.jsonify(self.alto.get_properties(pid))
            #return flask.jsonify({"ERROR" : ERRORES["sintax"], "syntax-error": "Method not valid. Required a POST request."})            

    
    
    
    
    ###################################
    ##                               ##
    #           Ampliations           #
    ##                               ##
    ###################################
    
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

    ### Desire6G ampliation
    #@self.app.route('/graphs/all', methods=['POST'])(self.api_graphs)
    def api_graphs(self):
        if flask.request.method == 'POST':
            data = flask.request.json
            #data = self.sanitize_input_POST(data)
            return flask.jsonify(str(self.alto.desire6g_graphs(data)))
        else:
            return flask.jsonify({"ERROR" : ERRORES["sintax"], "syntax-error": "Method not valid. Required a POST request."})


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
