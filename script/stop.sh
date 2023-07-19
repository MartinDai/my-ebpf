#!/bin/bash

set -e

STR=`ps -ef | grep "my-ebpf" | awk  -F ' '  '{print $2}'`
if [ ! -z "${STR}" ]; then
    kill -9 ${STR} > /dev/null 2>&1
    sleep 2
    echo "Stop agent successful"
else
  echo "没有agent进程"
fi
