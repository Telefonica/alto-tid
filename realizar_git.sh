#/bin/bash

git init
git add .
git reset api/web/certs/*
git reset alto_fed/*
git reset kafka_ale/*
git reset alto_local/*
#git reset __pycache__/*
git reset __pycache__
git commit -m $( date +"%s" )
git push origin main
