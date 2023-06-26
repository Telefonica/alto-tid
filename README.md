



## Tabla de contenidos
1. [Descripción general](#descripcion-general)
2. [Lista de archivos](#lista-de-archivos)
3. [Jerarquía de archivos](#jerarquía-de-archivos)
4. [Versiones](#versiones)
5. [ToDo list](#todo-list)


### Descripción general
Directorio creado para realizar una revisión del código para ver si lo podemos adaptar a un contexto en el cual se sincronice con una cola kafka. 
Este sistema idealmente sería distribuído y tolerante a fallos.

El principal objetivo de este directorio es toquetear el código sin fastidiar nada de lo que han hecho los compañeros previamente, valiéndonos de una copia.

Debemos además realizar la evaluación de qué tenemos que implementar para que tengamos un servidor ALTO plenamente funcional.
Revisar cómo pasar a python los trabajos que hemos hablado Contreras, Rafa y yo.

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

### RFC 7285
+ Funcionalidades:
	+ Faltan:
		+ Mostrar el Content-Type en las cabeceras HTTP
		+ Modificar el Cost-endpoint para que muestre los costes respecto a los endpoints y no los routers
		+ Falta implementar el filtrado del networkmap
		+ Capabilities: WTF is this
+ Formateado:
	+ Falta:
		+ Depurar el formato YANG
		+ Formato de errores
		+ Gestión de cabeceras



### Versiones

v0.1
Esta versión es la original. Es una versión casi completa del RFC7285, pero con todas las funcionalidades que nos van a hacer falta para el DISCRETION.

### ToDo List

***

1. Cifrado de PIDs. (done)
2. Mostrar solamente nodos barrera. (done)
3. Incluir la exposición a través de Kafka.
4. Pulir la exposición a través de Kafka.
5. Parsear todas las respuestas a formato YANG.

***




