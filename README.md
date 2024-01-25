



## Table of Contents
1. [General Description](#general-description)
2. [Lista de archivos](#lista-de-archivos)
3. [Jerarquía de archivos](#jerarquía-de-archivos)
4. [Versiones](#versiones)
5. [ToDo list](#todo-list)


### General Description
This code is an ALTO's special implementation ussed in different european projects, being the Discretion application the main one used as root for this. ALTO is a 


### Lista de archivos

* exponsure.py: Proporciona una API de acceso vía HTTP a los servicios definidos en el RFC7285.
* topology_maps_creator.py: Lanza los módulos ALTO disponible y recibe la información de topología a partir de una interfaz habilitada para ello. Si se le indica al ejecutarlo, crea además una cola Kafka donde publicará la información de topología de red.
* yang_alto.py: Estandariza la salida de la información siguiendo un esquema YANG y en formato JSON.
* kafka_ale:
	* launcher: Archivo sh que ejecuta tanto el entorno zookeaper como la cola Kafka.
	* kafka_api.py: Proporciona una API python para trabajar con la cola definida.
	* resto de carpetas y archivos: Archivos de gestión para Kafka y Zookeaper.
* Modulos:
	* alto_module.py: Clase abstracta que define el comportamiento de los distintos ALTO modules. El objetivo es tener una API conjunta de manera que todos los módulos tengan la misma base y las mismas funciones principales para exportar la información recibida.
	* topology_bgp.py: Módulo ALTO que procesa la información recibida vía BGP.
	* topology_ietf.py: Módulo ALTO que procesa la información recibida del PCE.
* ../bgp/manage_bgp_speaker.py: Speaker del protocolo GBP. Implementa el proceso exabgp para recopilar información de red. No ha sido modificado pero lo debemos tener en cuenta dado que dependemos de él.
* realizar_git: script de actualización del repositorio git. Tengo que modificarlo para pasarlo al git oficial de Telefónica.

Archivos en desuso (/desuso/):
* api_pybatfish.py: Intento de integración con bathfish. Se canceló al ver que no sacábamos una ventaja de esta integración. No se ha eliminado al existir aún la posibilidad de reutilizar esa idea más adelante.
* topology_maps_creator_isis.py: Similar al topology_maps_creator.py pero utilizando ISIS como E-BGP. Se ha dejado de lado en las primeras versiones (no llegó a la fase de ramificaciones) debido a que no exportaba bien la topología de red. Actualmente con el funcionamiento modular podría servir como germen de un módulo nuevo, pero aún no se ha evaluado cómo realizar esto o si sale rentable.
* launcher_batfish: script de activación del pybatfish. Idem a api_pybatfish.py.
* modulos/topology_maps_generator.py.bk: Copia de seguridad de la última versión unificada del generador original.



### Jerarquía de archivos

+ exponsure --> API de exposición en red de ALTO.
	+ alto_generator --> expone: funciones RFC7285 desarrolladas.
		+ topologia_ietf: expone: grafo de red.
			+ ?
		+ topologia_bgp --> expone: grafo de red.
			+ bgp.manager_bgp_speaker --> expone: info periódica de actualizaciones BGP.
		+ yang_alto --> expone: formateo de datos a YANG JSON.
		(+) kafka_api --> expone: capacidad de enviar a una cola kafka la info recibida.
+ launcher --> Activa la opción con kafka_api



### Versiones

v3.0 (en proceso)
Incluímos las funcionalidades de la versión 2 aplicándoselo también si la fuente es IETF en vez de BGP.
Falta:
	- Terminar la definición de propiedades.
	- Una vez esté todo correcto, extraer tanto el lector bgp como el lector ietf a dos archivos distintos.
	- Modificar las funciones auxiliares para que puedan utilizarse en ambos tipos de topología.


v2.1
Añadimos todos los servicios ofrecidos por ALTO en el rfc7285:
* Map-Filtering Service: Realiza un resumen del mapa de costes o PIDs a partir de un parámetro pasado.
* Endpoint Property Service: Devuelve un JSON con las características del nodo solicitado.
* Endpoint Cost Service: Devuelve el mapa de costes del Endpoint solicitado.
* Map Service: Servicio que se ha definido por defecto. Devuelve los dos mapas que se generaban hasta ahora.

- Modificado el formato de los networkmap para que indiquen no solo las IPs, sino también el tipo de IP, tal y como se especifica en el RFC7285.
- Creado un archivo que sirva de codificador json-yang. Falta:
	- Casos que aún no están implementados tampoco están formateados (por pereza, por poder lo podría haber hecho).
	- Realizar pruebas con más de 1 prefijo por PID en el networkmap.
	- Seguir revisando condiciones del RFC.

v2.0
Dividimos el proyecto en dos:
- topology_maps_generator_http.py: Orientado a un servicio C/S. Se busca exponer funciones que sean accesibles desde el exterior.
- topology_maps_generator_kafka.py: Orientado a una exposición unidireccional. 

Para simplificar el desarrollo se puede realizar todo en la misma rama pero incluyendo un argumento que elija la versión para lanzar.
Esta versión va en paralelo con la v1.2, de manera que aclopará esos cambios.

    ***
        Hay que crear funciones para exponer los servicios que prestamos:
        - Multimaps (DONE)
        - CostesCifrados (?)
        - Echo (para debugin) (DONE)
        Cada conexión http un hilo (?) --> Hay que revisar documentación, cómo crear el servicio, cómo exponerlo (en claro o bajo SSL), ... (DONE: versión inicial)
        Importante --> Lista de puntos pendientes
    ***
Servicios expuestos: multipath, costs, pids, best path


PARA FUTURAS VERSIONES: Posibilidad de devolver un PDF de un grafo de red.

v1.2 (en desarrollo)
Revisar la viabilidad de utilizar el batfish.
Incluir la opción de mostrar todos los caminos disjuntos para llegar de un punto a otro de la red delimitada. (done)
Hacer que la opción de caminos disjuntos sea preguntable desde un externo: Problema, la cola Kafka es unidireccional (dos opciones, realizar un branch sin colas kafka o utilizar otro método de exposición)


v1.1
Ciframos el PID de los nodos con un hash sha3 de 384bits, utilizando un timestamp como salt. Para evitar nombres muy largos acotamos a los 32 caracteres más significativos 
(Dado que la intención es enmascarar la IP, no se pierde seguridad al reducir los bits mostrados)
En paralelo Fer ha estado incluyendo conexiones ponderadas.


v1.0
Instalamos una cola kafka activable mediante ./kafka_ale/launcher. Dependencias: Zookeper
Creamos un archivo python que servirá de API para trabajar con la cola kafka.
Versión inicial: 2 colas (mapa_costes y mapa_pids).

Falta por definir en fase 2:
- Que la cola solamente almacene los 2-3 registros más recientes (no hacen falta más al no consumirse al ser accedidos a ellos).
- Accesible mediante conexión SSL.
- Posibilidad de colas distribuídas.
- Script de gestión de fallos.

Además, hemos sustituído el grafo Direcional simple por un grafo unidireccional Múltiple (permite más de 1 enlace entre dos nodos).


v0.1
Hemos modificado el código de topology_maps_generator.py y topology_maps_generator_isis.py para que si se cae un nodo no generen una excepción, sino que eliminen los enlaces que han desaparecido.
La funcionalidad básica está correcta en ospf pero en isis no se propagan las solicitudes a routers no colindantes.


### Execution

Terminal 1:
$ cd alto-eucnc/
$ python3 alto_core.py

Terminal 2:
$ curl -X POST -d '{"filter": "qkd"}' -H "Content-Type:application/json" http://127.0.0.1:5001/maps
$ curl http://127.0.0.1:5001/qkd-properties/"pid0:02020201"
$ curl http://127.0.0.1:5001/qkd-properties/yang


### Notas
Pausamos la inclusión de Kafka dado que con un solo Productor no tiene demasiado sentido. Además, podríamos buscar una forma de estandarizar esta salida, para que sirva para más de un tipo de colas... 
En teoría en las colas hay mínimo tres actores: Broker o gestor de la cola, Productor y Consumidor.
El Broker y el Productor no son lo mismo, tienen que ir separados.


