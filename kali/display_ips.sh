#!/bin/bash

interface="eth0"
ip=$(ip addr show $interface 2>/dev/null | grep -oP 'inet \K[\d.]+')

if [[ $ip != "" ]]; then
        echo -e "$interface:\t$ip"
else
        echo -e "$interface:\tnot connected"
fi

interface="tun0"
ip=$(ip addr show $interface 2>/dev/null | grep -oP 'inet \K[\d.]+')

if [[ $ip != "" ]]; then
        echo -e "$interface:\t$ip"
else
        echo -e "$interface:\tnot connected"
fi
