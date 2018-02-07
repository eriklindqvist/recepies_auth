#!/bin/sh

CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o auth .
docker build -t recepies_auth .
docker tag recepies_auth:latest proto:5000/recepies_auth
