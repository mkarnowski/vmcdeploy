#!/bin/sh


DOCKER_IMAGE="mkarnowski/vmcdeploy:20.1.5"
  
echo $1

file1=$(cat $1)


docker run -t --rm -e "EN_CONFIGURATION=$file1" "$DOCKER_IMAGE"


        
