#!/bin/bash
set -ex
here=$(realpath $(dirname "$0"))
cd "$here"

if [ -z ${1+x} ] ; then
    echo "missing tag"
    exit 1
fi

export TAG=$1

docker build -t leaksignal/leaksignal-operator:$TAG-amd64 -f ./Dockerfile .
docker push leaksignal/leaksignal-operator:$TAG-amd64
docker image rm leaksignal/leaksignal-operator:$TAG-amd64

docker build --platform linux/arm64 -t leaksignal/leaksignal-operator:$TAG-arm64v8 -f ./Dockerfile.arm64v8 .
docker push leaksignal/leaksignal-operator:$TAG-arm64v8
docker image rm leaksignal/leaksignal-operator:$TAG-arm64v8

docker manifest create \
    leaksignal/leaksignal-operator:$TAG \
    --amend leaksignal/leaksignal-operator:$TAG-amd64 \
    --amend leaksignal/leaksignal-operator:$TAG-arm64v8
docker manifest push leaksignal/leaksignal-operator:$TAG

echo "Uploaded image leaksignal/leaksignal-operator:$TAG"

docker build -t leaksignal/leaksignal-operator:$TAG-ubi -f ./Dockerfile.ubi .
docker push leaksignal/leaksignal-operator:$TAG-ubi
docker image rm leaksignal/leaksignal-operator:$TAG-ubi

cp -f ./crds/* ./chart/crds/

helm package -d ./helm_upload/ ./chart

helm push ./helm_upload/*.tgz oci://registry-1.docker.io/leaksignal

rm -rf helm_upload

# ./olm/publish_bundle.sh $TAG