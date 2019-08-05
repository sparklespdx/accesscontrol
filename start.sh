#!/bin/bash
exec &>/dev/null

PID=`pidof python`
if [ -z "$PID" ]; then
	cd /root/ac/
	if [ ! -d conf ]; then
		mv conf-examples conf
	fi
	python access.py &> debug.log &
fi
