



## Table of Contents
1. [General Description](#general-description)
2. [Files Lists](#files-lists)
3. [Versions](#versions)
4. [Execution](#execution)
5. [Contact](#contact)
6. [License](#license)


### General Description
This code is an ALTO's special implementation ussed by TID in different european and Mineco projects.

Application Layer Traffic Optimisation Protocol (ALTO) is a network protocol standardised by the Internet Engineering Task Force (IETF) that provides information about network topology and the location of network resources based on the hops required to access each node. The ALTO protocol allows applications to make informed decisions on how to optimise the use of network resources and reduce congestion. For example, a video streaming application could use the ALTO protocol to obtain information about the location of content servers and select the server that is closest to the user and has the least traffic load at that time.

Currently we have 5 active branches:
1. Completo. Main branch, here we integrate the code already tested from the rest of the branches.
2. Discretion. Branch dedicated to the code developed under the DISCRETION project (GA: ). The main feature here is the secure expossition of QKD capabilities in the network. There are two activities lines: the data expossure limitation and the QKD information integration and expossure.
3. Desire. Branch dedicated to the code developed under the Desire6G project (GA:). The main functionalities are related to the expossition of paths and graphs for be used by a AI-based deployment module.
4. Energy. Branch dedicated to the code developed under the 6Green project (GA:). The main functionalities are related with the integration and expossition of power metrics.
5. Multimetrica. Branch dedicated to the code developed under the Optimaix project (GA:). This code includes the funtionalities of Cost Calendar and the expossition of more than one metric as the client requests.

### Files list

* [alto_core.py](alto_core.py): Main document of the git. It includes the logic of ALTO protocol.
* [config.yaml](config.yaml): Includes the diferent variables of ALTO code. It allows modifying IPs, ports and add-ons.
* [yang_alto.py](yang_alto.py): Standardises the output of information following an ALTO schema and in JSON format.
* [api/desire/alto_http.py](api/desire/alto_http.py): Provides an API for HTTP access to the services defined in RFC7285 and the ampliations offered in our PoC.
* [modulos/alto_module.py](modulos/alto_module.py): Abstract class that defines the behaviour of the different ALTO modules. The objective is to have a joint API so that all modules have the same base and the same main functions to export the information received.
* [modulos/topology_bgp.py](modulos/topology_bgp.py): ALTO module that processes the information received via BGP.
* [modulos/topology_ietf.py](modulos/topology_ietf.py): ALTO module that processes the information received from the Network Controller.
* [modulos/bgp/manage_bgp_speaker.py](modulos/bgp/manage_bgp_speaker.py): BGP protocol speaker. It implements the exabgp process to collect network information. It has not been modified but we should be aware of it as we depend on it.
* [pruebas/](pruebas/): Folder with results obtained during the experimentations. Example of the results to be obtained.
* [endpoints/properties.json](endpoints/properties.json): Documment with the nodes' properties used as input to obtain the DC information.


### Versions

All versions are related over the main branch (completo):

v1.0
Version with the main capabilities expossed in RFC7285:
* Map-Filtering Service: Retunr a view of the resources firtering them by a parameter indicated by the client.
* Endpoint Property Service: It returns the properties of a indicated endpoint.
* Endpoint Cost Service: Returns the cost to a endpoint.
* Map Service: Default service, it returns the two main resources expossed by ALTO: the network-map and the cost-map. They are also available separated.

- Modified the networkmap format to indicate not only the IPs, but also the IP type, as specified in RFC7285.
- Created a file to serve as a json-yang encoder. Missing:
	- Cases that are not yet implemented are also not formatted (out of laziness, by proxy I could have done it).
	- Testing with more than 1 prefix per PID in the networkmap.
	- Keep checking RFC conditions.

v1.1
Including the module to read IETF topology.

v1.2


### Execution

Terminal 1:
```
$ cd alto/
$ python3 alto_core.py
```

Terminal 2:
```
$ curl 127.0.0.1:8082/ 
```

### Esquemas
Example of ALTO topology with the three main elements:
![ALTO topology](https://github.com/Telefonica/alto-tid/blob/completo/images/ALTO-example-topology.png)

Three main elements in ALTO maps:
![ALTO elements](https://github.com/Telefonica/alto-tid/blob/completo/images/ALTO-elements.png)



### Contact

Alejandro Muñiz Da Costa: alejandro.muniz@telefonica.com

Luis Miguel Contreras Murillo: luismiguel.contrerasmurillo@telefonica.com


### Our team

Alejandro Muñiz Da Costa

Luis Miguel Contreras Murillo

Paula Aguado De Cabo

Alberto Solano (ex partner)


## License 
© 2024 Telefónica Innovación Digital

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
