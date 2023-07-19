#!/bin/bash

set -e

rm -rf ./bin/ || true
mkdir ./bin

VERSION=$(cat version.txt)
IMAGE_NAME=my-ebpf:${VERSION}

docker buildx build -t ${IMAGE_NAME} --platform=linux/amd64 -o type=docker .

CID=$(docker create ${IMAGE_NAME})
FILE_PATH=$2
LOCAL_PATH=$3
docker cp ${CID}:/usr/bin/my-ebpf ./bin/
docker rm -v ${CID}