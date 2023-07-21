#!/bin/bash

set -e

ARCH=$1

if [ -z "$ARCH" ]; then
    echo "错误：未指定ARCH参数。"
    exit 1
fi

if [ "$ARCH" != "amd64" ] && [ "$ARCH" != "arm64" ]; then
    echo "错误：ARCH参数必须是amd64或arm64。"
    exit 1
fi

rm -rf ./bin/ || true
mkdir ./bin

BUILD_NAME=my-ebpf
VERSION=$(cat version.txt)
IMAGE_NAME=${BUILD_NAME}:${VERSION}

docker buildx build -t ${IMAGE_NAME} --platform=linux/${ARCH} -o type=docker .

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