#!/usr/bin/env python3
# © 2024 Telefónica Innovación Digital, All rights reserved


import networkx
from flask import Flask, request, jsonify
from time import sleep
from modulos.alto_module import AltoModule
from werkzeug.serving import make_server


RR_BGP_0 = "50.50.50.1"
#RR_BGP = BGP_INFO['bgp']['ip']
MAX_VAL = 16777214
time_interval_size = 120 #seconds
number_of_intervals = 5

class TopologyNDT(AltoModule):

    def __init__(self, mb):
        super().__init__(mb)
        '''        self.ietf_process = 0
        self.props = {}
        self.pids = {}'''
        self.topology = networkx.Graph()
        self.cost_map = {}
        self.router_ids = []
        self.list_topologies = []
        self.ts = {}
        self.app = Flask("http")
        self.app.config["DEBUG"] = True
        self.app.route('/', methods=['GET'])(self.home)
        self.app.route('/update-expected-topology', methods=['POST'])(self.api_cost_calendar_cs)

    def run(self):
        #self.app.run(host="127.0.0.1", port=5000)
        self.server = make_server("0.0.0.0", "9999", self.app)
        #self.server = make_server('192.168.165.193', 8080, self.app)
        print("API running on " + "\x1b[1;34m" +"http://127.0.0.1:9999" + "\x1b[1;37;40m")
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
    
    ### Manager function       
    def manage_topology_updates(self):
        while 1:
            #sleep(15)
            sleep(5)
            self.manage_updates()

    def api_cost_calendar_cs(self):
        print(f"Info recibida:\t{request}")
        if request.method == 'POST':
            data = request.json
            cost_calendar_start_time = data.get('calendar_start_time', [])
            #cost_calendar_start_time_tuple = tuple(map(int, cost_calendar_start_time.split(',')))
            update_topology = data.get('update_topology', "")
            print(f"Info received:\t{update_topology}")
            self.manage_updates(cost_calendar_start_time, update_topology)
        return jsonify("Costcalendar Created")



    def manage_updates(self, cost_calendar_start_time, update_topology):
        '''
        Receives topology information from the PCE by the Southaband Interface and creates/updates the graphs
        Realizes an iterational analisis, reviewing each network: if two networks are the same but by different protocols, they must to be merged.
        Three attributes on each network: dic[ips], dic[interfaces] and graph[links]
        '''
        if update_topology != "":
            data = {"pids":"","nodes-list": "","costs-list": "","prefixes": "", "topology":update_topology, "start-time":cost_calendar_start_time }
            self.return_info(5,0,1, data)
                        

