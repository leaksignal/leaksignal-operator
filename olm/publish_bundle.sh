#!/bin/bash
set -ex
here=$(realpath $(dirname "$0"))
cd "$here"

if [ -z ${1+x} ] ; then
    echo "missing tag"
    exit 1
fi

export TAG=$1

docker build -t leaksignal/leaksignal-operator-olm:$TAG .
docker push leaksignal/leaksignal-operator-olm:$TAG

echo "Uploaded bundle leaksignal/leaksignal-operator-olm:$TAG"

docker build \
    -f ./catalog.Dockerfile \
    -t leaksignal/leaksignal-operator-olm:$TAG-index \
    .

docker push leaksignal/leaksignal-operator-olm:$TAG-index

echo "Uploaded index leaksignal/leaksignal-operator-olm:$TAG-index"
