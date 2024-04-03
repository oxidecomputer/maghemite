#!/bin/bash

#docker network create --driver bridge oxpop_isp
docker network create --driver bridge oxpop_cdn
docker network create --driver bridge oxpop_pubcloud

docker network connect oxpop_cdn oxpop
docker network connect oxpop_cdn cdn

docker network connect oxpop_pubcloud oxpop
docker network connect oxpop_pubcloud pubcloud
