#!/bin/bash

if [ $# -eq 1 ];
then
	sudo iptables -A OUTPUT -p TCP --tcp-flags RST RST -d "$1" -j DROP
	echo "Uspesno blokirani RST flegovi za $1 adresu"
else
	echo "Usage: sudo ./iptables.sh <IP ADRESA>"
fi
