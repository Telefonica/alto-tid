#/bin/bash

git init
git add .
git add api/web/certs/README.md
git reset kafka_ale/logs/*
#git reset __pycache__/*
git reset __pycache__
git commit -m $( date +"%s" )
git push origin federation
