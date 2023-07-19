#!/bin/bash

set -e

SHELL_HOME="$(cd "$(dirname "$0")" && pwd)"

nohup ${SHELL_HOME}/my-ebpf -config ${SHELL_HOME}/config.yml > ${SHELL_HOME}/agent.log 2>&1 &

echo "Agent started, please go to the directory ${SHELL_HOME}/agent.log to view the logs."
