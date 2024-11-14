#!/bin/bash

python3 alto_core.py &
sleep 10
echo "Starting tests"
curl localhost:8888/costmap
sleep 2
curl localhost:8888/costcalendar
sleep 2
echo "Client API checked, time to check the update API"
sleep 1
TIMESTAMP=$(date -d "+5 minutes" +"[%Y, %m, %d, %H, %M, %S]")
topology=$(cat topology_metrics.json)
curl -X POST -d '{"calendar_start_time":'$TIMESTAMP',"update_topology":'$topology'"}' -H "Content-Type: application/json" http://localhost:9999/update-expected-topology

