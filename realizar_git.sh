#/bin/bash

git init
git add $*
git commit -m $( date +"%s" )
git push origin main
