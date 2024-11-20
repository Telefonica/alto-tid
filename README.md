



## Table of Contents
1. [General Description](#general-description)
2. [Files Lists](#files-lists)
3. [Versions](#versions)
4. [Execution](#execution)
5. [Contact](#contact)
6. [License](#license)


## General Description

### What is the ALTO Protocol?

The Application-Layer Traffic Optimization (ALTO) protocol, defined in [RFC 7285](https://www.rfc-editor.org/info/rfc7285), is designed to help applications optimize their network traffic by providing them with abstracted, high-level network information from the perspective of network operators. Typically, applications such as content delivery networks (CDNs) or peer-to-peer (P2P) sharing systems need to make decisions about which endpoints to connect to for efficiency and performance. The ALTO protocol supports this by offering a view of the network topology and cost structure, helping applications select the best endpoints based on network conditions.

### How ALTO Works

ALTO provides applications with two main types of information:

1. **Network Maps**: These maps represent the network topology and group endpoints by location within the provider’s network, using Provider-defined Identifiers (PIDs). Each PID can represent specific IP ranges, enabling applications to understand the broader layout of the network without detailed topology exposure.
   
2. **Cost Maps**: Cost maps specify the cost metrics between pairs of PIDs or endpoints. These costs can include factors such as latency, bandwidth, or general routing costs. Cost maps give applications the ability to select optimal paths or endpoints based on the criteria set by network operators.

The ALTO protocol follows a RESTful design and uses JSON for data encoding, making it straightforward for applications to request network maps and cost information from an ALTO server. ALTO allows applications to balance performance with network efficiency by choosing paths that avoid congested or costly network segments.

---

### What is Time-Variant Routing (TVR)?

Time-Variant Routing (TVR) addresses situations where network routing changes over time due to predictable events, such as scheduled maintenance, network upgrades, or known periods of high traffic. TVR captures these anticipated routing changes and makes them available so applications and systems can adjust proactively.

#### The Problem of TVR

In dynamic network environments, routing and connectivity often vary across time. For example, during network maintenance, certain paths may become unavailable or have reduced performance. If applications are not aware of these changes in advance, they may experience degraded performance or even failures in connectivity. TVR aims to make these time-based routing changes predictable and available to applications so they can adapt their behavior accordingly.

TVR can integrate with network controllers to schedule and manage changes, and these controllers may use algorithms or simulations (like network digital twins) to predict and evaluate the impacts of routing adjustments. However, TVR also requires a mechanism to share this time-variant information with external applications.

---

#### How ALTO Can Help Expose TVR-Related Changes

ALTO can serve as a tool to expose the future changes in routing that TVR manages, providing applications with a way to become aware of these scheduled routing modifications. The ALTO protocol includes a feature known as the **ALTO cost calendar** (specified in [RFC 8896](https://www.rfc-editor.org/info/rfc8896)), which allows the ALTO server to present cost information over time.

#### Using ALTO Cost Calendars for TVR

The ALTO cost calendar enables applications to view upcoming network costs and routing changes in a structured time-based format. This feature provides time-related attributes such as:

- **Calendar Start Time**: The date and time when the cost calendar begins.
- **Time Interval Size**: The duration of each time interval in seconds.
- **Number of Intervals**: The number of entries in the calendar.
- **Repeated**: An optional attribute indicating how many times the calendar values repeat.

By using these attributes, the ALTO cost calendar can expose anticipated changes in routing metrics due to TVR events. This setup allows applications to adjust routing decisions based on upcoming network conditions, helping them avoid potential performance issues by routing around affected paths. ALTO thus acts as a bridge for TVR, facilitating time-variant routing information access for applications and supporting better network and application performance.

---

## Files list

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


## Versions

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


## Execution and testing

The testing comands can vary depending on the deep desired, although, in here we are proposing a minimum set of commands to test the main workflow:

```
python3 alto_core.py 
curl localhost:8888/costmap # In other terminal
curl localhost:8888/costcalendar
TIMESTAMP=$(date -d "+5 minutes" +"[%Y, %m, %d, %H, %M, %S]")
topology=$(cat topology_metrics.json)
curl -X POST -d '{"calendar_start_time":'$TIMESTAMP',"update_topology":'$topology'"}' -H "Content-Type: application/json" http://localhost:9999/update-expected-topology
```

These commands are also available in [test.sh](test.sh) file.

## Contact

- Alejandro Muñiz Da Costa: alejandro.muniz@telefonica.com
- Luis Miguel Contreras Murillo: luismiguel.contrerasmurillo@telefonica.com

### Acknoledgmends

Paula Aguado de Cabo