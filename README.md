



## Table of Contents
1. [General Description](#general-description)
2. [Files Lists](#files-lists)
3. [Versions](#versions)
4. [Execution](#execution)
5. [Contact](#contact)
6. [License](#license)


### General Description
This code is an ALTO's special implementation ussed by TID in DISCRETION european project. This work has been partial funded by the European Union through the European Defence Industrial Development Programme (EDIDP)’s DISCRETION project, with grant agreement No SI2.858093.

Application Layer Traffic Optimisation Protocol (ALTO) is a network protocol standardised by the Internet Engineering Task Force (IETF) that provides information about network topology and the location of network resources based on the hops required to access each node. The ALTO protocol allows applications to make informed decisions on how to optimise the use of network resources and reduce congestion. For example, a video streaming application could use the ALTO protocol to obtain information about the location of content servers and select the server that is closest to the user and has the least traffic load at that time.
In this project, ALTO server will work as a Federation technology to help a SD-QKD Controller to identify how to reach to a node outside it's administration domain. 
There will be two main functionallities:
* ALTO to exposse information about the optimal Bordernode to be used (decide by the lowest hop-count).
* ALTO to exposse QKD link information to stablish connection with the other SD-QKD BorderNode.

#### APIs to be used
Considering an API service running at 10.0.0.11:8080/. There are the next requests to be realized:

* http://10.0.0.11:8080/  : Request for information about available APIs to be used.
	* ``` shell	
		$ curl http://10.0.0.11:8080/
		$ {
			"message": "ALTO PoC's API", 
			"services": "
				ALTO PoC's API
				Services expossed:
				    1. Costs map: /costmap ['GET']           
					2. Filtered Cost map: /costmap ['POST']             -> Parameters: Node-ID as node            
					3. QKD Link Properties: /qkd-properties ['POST']    -> Parameters: QKD Link Properties as link            
					4. Border Node Information: /get-bordernode ['POST']-> Parameters: Node-ID as node
		        "
			}	
	```
* http://10.0.0.11:8080/get-bordernode : If a node is not in our administration domain, this API can ask others ALTO servers for information about a requested node:
	* ```shell	
			$ curl -X POST -d '{ "node" : "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz" }' -H "Content-Type: application/json" http://10.0.0.11:8080/get-bordernode
			$ "{'border-node': 'cccccccc-cccc-cccc-cccc-cccccccccccc', 'remote': 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'}" 
		```
* http://10.0.0.11:8080/qkd-properties : Request for QKD link propperties. 
	* ``` shell	
		$ curl -X POST -d '{ "node":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" }' -H "Content-Type: application/json" http://10.0.0.11:8080/qkd-properties
		$ {'header':{'Content-Type': 'application/alto-endpointprop+json'}, 'meta':{'dependent-vtags': [{'resource-id': 'networkmap-default', 'tag': '1713949998033325'}]}, 'property': {'qkdn_id': 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', 'qkdi_id': 2}}	
		```



### Files list

* [alto_core.py](alto_core.py): Main document of the git. It includes the logic of ALTO protocol.
* [config.yaml](config.yaml): Includes the diferent variables of ALTO code. It allows modifying IPs, ports and add-ons.
* [yang_alto.py](yang_alto.py): Standardises the output of information following an ALTO schema and in JSON format.
* [api/web/alto_http.py](api/web/alto_http.py): Provides an API for HTTP access to the services defined in RFC7285 and the ampliations offered in our PoC.
* [modulos/alto_module.py](modulos/alto_module.py): Abstract class that defines the behaviour of the different ALTO modules. The objective is to have a joint API so that all modules have the same base and the same main functions to export the information received.
* [modulos/topology_qkd.py](modulos/topology_qkd.py): ALTO module that processes the information received from the SD-QKD Controller.
* [maps/](maps/): Folder with other local files with information required to provide services.
* [maps/qkd-topology.py](maps/qkd-topology.py): JSON with the topology information from the local network.
* [endpoints/qkd-nodes.json](endpoints/qkd-nodes.json): Documment with the nodes' properties used as input to obtain the SD-QKD Nodes' information.





### Installation
In each repository, it is needed to download the code from discretion branch:
```
mkdir alto-dis
git clone git@github.com:Telefonica/alto-tid.git alto-dis/ && cd alto-dis
git checkout discretion
```
Once the code is downloaded, in config.yaml it is needed to configure the port to be used to exposse the ALTO server:
API_PORT: 8082
Then, in alto_core.py configure the list of known_servers (__init__ function). 
For example, if one server is running at 10.0.0.11:8080 and the other at 10.0.0.12:8080, it has to modify it as following:
```
self.known_servers = [ ["10.0.0.11", 8080], ["10.0.0.12",8080]]
```
Also, there should be saved the next docs at maps/ folder:
* qkd-topology.json : Topology with the devices and links. 
* qkd-nodes.json    : Information about interfaces, nodes, links and capabillities.

Currently there are two different versions as example: 
* qkd-topology.json/qkd-nodes.json               : Includes information about nodes and links in a 1st domain with 3 nodes: A, B and C.
* qkd-topology-remote.json/qkd-nodes-remote.json : Includes information about nodes and links in a 2nd domain with 3 nodes: X, Y and Z.

### Execution

Terminal 1, machine 1:
```
$ cd alto-dis/
$ python3 alto_core.py
```

Terminal 1, machine 2:
```
$ cd alto-dis/
$ python3 alto_core.py
```


### Contact

Alejandro Muñiz Da Costa: alejandro.muniz@telefonica.com
Luis Miguel Contreras Murillo: luismiguel.contrerasmurillo@telefonica.com

