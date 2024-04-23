#!/bin/bash

greenplus="\e[1;33m[+]\e[0m"
yellowstar="\e[1;33m[*]\e[0m"
redexclaim="\e[1;31m[!]\e[0m"

if [ $EUID -ne 0 ]; then
    echo -e "\n  $redexclaim Script must be run with 'sudo ${0##*/}' or as root!\n"
    exit 1
fi

echo -e "\n  $yellowstar Stopping containers ...\n"
docker container stop $(docker container ls -q) 2>/dev/null

echo -e "\n  $yellowstar Removing containers ...\n"
docker container rm $(docker container ls -aq) 2>/dev/null

echo -e "\n  $yellowstar Removing images ...\n"
docker image rm $(docker image ls -aq) 2>/dev/null

echo -e "\n  $yellowstar Removing volumes ...\n"
docker volume rm $(docker volume ls -q) 2>/dev/null

echo -e "\n  $yellowstar Removing cached data ...\n"
docker system prune -f

echo -e "\n  $greenplus Done!\n"
