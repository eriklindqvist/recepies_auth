# recepies_auth
Authorization service for the Recepies project

## Setup
Create a pair of private/public keys
```
$ openssl genrsa -out certs/private.rsa 2048
$ openssl rsa -in certs/private.rsa -pubout > certs/public.rsa
```
