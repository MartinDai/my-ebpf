#!/bin/bash

set -e

rm -rf ./bin/ || true
mkdir ./bin

BUILD_NAME=my-ebpf
VERSION=$(cat version.txt)
IMAGE_NAME=${BUILD_NAME}:${VERSION}

ARCH=$1
if [ -n "$ARCH" ]; then
    if [ "$ARCH" != "amd64" ] && [ "$ARCH" != "arm64" ]; then
        echo "错误：ARCH参数必须是amd64或arm64。"
        exit 1
    fi
    docker buildx build -t ${IMAGE_NAME} --platform=linux/${ARCH} -o type=docker .
else
    docker build -t ${IMAGE_NAME} .
fi

CID=$(docker create ${IMAGE_NAME})
docker cp ${CID}:/usr/bin/my-ebpf ./bin/
docker rm -v ${CID}

rm -rf ./${BUILD_NAME}/ || true
mkdir ./${BUILD_NAME}

cp ./bin/my-ebpf ./${BUILD_NAME}/my-ebpf
cp ./script/start.sh ./${BUILD_NAME}/start.sh
cp ./script/stop.sh ./${BUILD_NAME}/stop.sh
cp ./script/config.yml ./${BUILD_NAME}/config.yml

tar zcf ${BUILD_NAME}.tar.gz ./${BUILD_NAME}/
rm -rf ./${BUILD_NAME}/