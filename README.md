# Transport Layer Security Hot Reload Sample

Sample project to demonstrate Spring Boot 3.2.x SSL hot-reload functionality. Shows both webserver certs and mtls certs reload.

## How to run

_NOTE: Generate the certs if <root>/certs folder is empty, see next section_

````bash
# clean, compile and run, starts the server
./mvnw clean compile 
./mvnw spring-boot:run
````

````bash
# start the client
SPRING_PROFILES_ACTIVE=client ./mvnw spring-boot:run
````
See `Sample Requests.http`

## Generate private key

````bash
# server key
openssl genrsa -out certs/server.key 2048
# client key
openssl genrsa -out certs/client.key 2048
````

## Generate certificate signing request

````bash 
# server csr
openssl req -new -key certs/server.key \
-out certs/server.csr \
-subj "/C=GB/ST=Berkshire/L=Reading/O=Example Corp/CN=localhost"

# client csr
openssl req -new -key certs/client.key \
-out certs/client.csr \
-subj "/C=GB/ST=Berkshire/L=Reading/O=Client Corp/CN=localhost"
````

## Generate self-signed certificate

````bash
# server self-sign
openssl x509 -req -days 365 \
-in certs/server.csr \
-signkey certs/server.key \
-out certs/server.crt

# client self-sign
openssl x509 -req -days 365 \
-in certs/client.csr \
-signkey certs/client.key \
-out certs/client.crt
````

## Generate keystore for JKS bundle

````bash
keytool -genkeypair -alias server \
-keyalg RSA -keysize 2048 \
-keystore src/main/resources/ssl/keystore.jks \
-validity 365 \
-storepass changeit \
-keypass changeit \
-dname "CN=localhost,OU=Example,O=Example Corp,L=San Francisco,ST=CA,C=US"
````

## Generate truststore

````bash
keytool -export -alias server \
-keystore src/main/resources/ssl/keystore.jks \
-file src/main/resources/ssl/server.cer \
-storepass changeit

keytool -import -alias server \
-file src/main/resources/ssl/server.cer \
-keystore src/main/resources/ssl/truststore.jks \
-storepass changeit \
-noprompt
````