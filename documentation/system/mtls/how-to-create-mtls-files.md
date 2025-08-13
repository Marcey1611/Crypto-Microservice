# How to create mTLS files for CryptoService and CryptoClient
The necessary mtls files are already generated and are placed in the correct directories.
You can find the necessary mtls files under the folowing links:
- [ca-files](../../../ca) includes:
  - root-ca.crt (Root CA certificate)
  - root-ca.key (Root CA private key)
- [server-files](../../../cryptoservice/src/main/resources/tls) includes:
  - server.crt (Server certificate)
  - server.csr (Server Certificate Signing Request)
  - server.key (Server private key)
  - server-cert.conf (Configuration file for server certificate generation)
  - server-keystore.p12 (Server keystore in PKCS12 format)
  - server-truststore.p12 (Server truststore in PKCS12 format)
- [client-files](../../../cryptoclient/src/main/resources/tls) includes:
  - client1.crt (Client certificate)
  - client1.csr (Client Certificate Signing Request)
  - client1.key (Client private key)
  - client1-keystore.p12 (Client keystore in PKCS12 format)
  - client1-truststore.p12 (Client truststore in PKCS12 format)
  - and the same files for client2.

It follows a step-by-step guide on how to create the necessary mTLS files for the CryptoService and CryptoClient, including the creation of a Root CA, server and client certificates, and keystores and truststores.
## 1. Create Root CA with OpenSSL
### 1.1. Create Root-Key
First, you need to create a root key for your Certificate Authority (CA).
```
openssl genrsa -out root_ca.key 4096
```
### 1.2. Create Root-Certificate (self-signed)
Next, create a self-signed root certificate using the key you just generated. This certificate will be used to sign the server and client certificates.
```
openssl req -x509 -new -nodes -key root_ca.key -sha256 -days 3650 -out root_ca.crt
```
You will be asked for details:
```
Country Name (2 letter code): DE
Organization Name: MyCryptoCA
Common Name: InternalCA
```
You can skip the other details by pressing Enter.
## 2. Create Certificates for Server & Client
### 2.1. Server (CryptoService)
Create a configuration file `server-cert.conf` with the following content:
```
[ req ]
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = localhost

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
```
Now you can generate the server key and Certificate Signing Request (CSR) using the configuration file you created.
```
openssl genrsa -out server.key 2048
```
```
openssl req -new -key server.key -out server.csr -config server-cert.conf
```
Finally, sign the CSR with your root CA to create the server certificate. This will allow the server to authenticate itself to clients.
```
openssl x509 -req -in server.csr -CA root-ca.crt -CAkey root-ca.key -CAcreateserial -out server.crt -days 365 -sha256 -extfile server-cert.conf -extensions v3_req
```
### 2.2. Client (CryptoClient)
Create a key and Certificate Signing Request (CSR) for the client. You can use a similar approach as for the server, but without the configuration file.
```
openssl genrsa -out client.key 2048
```
```
openssl req -new -key client.key -out client.csr -subj "/C=DE/O=Client/CN=client1"
```
Finally, sign the CSR with your root CA to create the client certificate. This will allow the client to authenticate itself to the server.
```
openssl x509 -req -in client.csr -CA root_ca.crt -CAkey root_ca.key -CAcreateserial -out client.crt -days 365 -sha256
```
## 3. Create Keystore & Truststore
### 3.1. Server
Now you can create a keystore and truststore for the server using the generated server.crt.
```
openssl pkcs12 -export -in server.crt -inkey server.key -out server-keystore.p12 -name server -CAfile root_ca.crt -caname root -passout pass:changeit
```
```
keytool -import -trustcacerts -alias root -file root_ca.crt -keystore server-truststore.p12 -storetype PKCS12 -storepass changeit -noprompt
```
### 3.2. Client
Now you can create a keystore and truststore for the client using the generated client.crt.
```
openssl pkcs12 -export -in client.crt -inkey client.key -out client-keystore.p12 -name client -CAfile root_ca.crt -caname root -passout pass:changeit
```
```
keytool -import -trustcacerts -alias root -file root_ca.crt -keystore client-truststore.p12 -storetype PKCS12 -storepass changeit -noprompt
```
## 4. CryptoService TLS-Config (Spring Boot)
Make sure that the application.properties or application.yml file of the CryptoService is configured correct. 
```
server:
port: 8443
ssl:
enabled: true
key-store: classpath:tls/server-keystore.p12
key-store-password: changeit
trust-store: classpath:tls/server-truststore.p12
trust-store-password: changeit
client-auth: need
```


