#!/bin/bash

set -ev

TRAVIS_DIR=`dirname $0`

HUGEGRAPH_LOADER_GIT_URL="https://github.com/hugegraph/hugegraph-loader.git"

git clone --depth 10 ${HUGEGRAPH_LOADER_GIT_URL}

cd hugegraph-loader
mvn install:install-file -Dfile=assembly/static/lib/ojdbc8-12.2.0.1.jar -DgroupId=com.oracle -DartifactId=ojdbc8 -Dversion=12.2.0.1 -Dpackaging=jar || exit 1
mvn package -DskipTests || exit 1
tar -zxf hugegraph-loader-*.tar.gz || exit 1
cd ../

hugegraph-loader/hugegraph-loader-*/bin/hugegraph-loader.sh  -g hugegraph -f ${TRAVIS_DIR}/struct.json -s ${TRAVIS_DIR}/schema.groovy || exit 1