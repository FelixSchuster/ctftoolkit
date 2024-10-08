#!/bin/bash

redexclaim="\e[1;91m[!]\e[0m"
greenplus="\e[1;92m[+]\e[0m"
yellowstar="\e[1;93m[*]\e[0m"

config_file="/opt/ctftoolkit/config/mate.conf"

echo -e "\n  $yellowstar Configuring the mate desktop environment ...\n"

cat $config_file | dconf load /org/mate/

echo -e "\n  $greenplus All Done! Happy Hacking!\n"
