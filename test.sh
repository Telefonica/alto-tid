#!/bin/bash

echo "Starting tests"
curl localhost:8888/costmap
sleep 2
curl localhost:8888/costcalendar
sleep 2
echo "Client API checked, time to check the update API"
sleep 1
# Actualizamos la segunda columna (timestamp para después de 5 minutos)
TIMESTAMP=$(date -d "+5 minutes" +"%Y-%m-%d %H:%M:%S.0000")
# Topología sin el nodo xvr14
TOPOLOGY=$(cat new_topology.json)
# Lo integramos en json
RESULT=$(jq -n --arg timestamp "$TIMESTAMP" --argjson topology "$TOPOLOGY" '{"calendar_start_time": $timestamp, "update_topology": $topology}')
# Por fin, ahora sí, creamos la solicitud
curl -X POST -d "$RESULT" -H "Content-Type: application/json" http://localhost:9999/update-expected-topology
sleep 2
curl localhost:8888/costcalendar
sleep 2
echo "Test finalized"
