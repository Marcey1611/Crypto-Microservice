# 1. Schritt-für-Schritt: Root CA erzeugen mit OpenSSL

## 1.1. Root Key erzeugen
```
openssl genrsa -out root_ca.key 4096
```

## 1.2. Root-Zertifikat (self-signed) erstellen
```
openssl req -x509 -new -nodes -key root_ca.key -sha256 -days 3650 -out root_ca.crt
```
Du wirst nach Details gefragt wie:
```
Country Name (2 letter code): DE
State or Province: Baden-Württemberg
Locality Name: Wangen
Organization Name: MyCryptoCA
Organizational Unit: DevCA
Common Name: InternalCA
Email Address: 
```



# 2. Zertifikate für Server & Client erstellen

## 2.1. SERVER (CryptoService):

### server-cert.conf

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

### Key + CSR
```
openssl genrsa -out server.key 2048
```
```
openssl req -new -key server.key -out server.csr -config server-cert.conf
```

### Mit Root-CA signieren
```
openssl x509 -req -in server.csr -CA root-ca.crt -CAkey root-ca.key -CAcreateserial -out server.crt -days 365 -sha256 -extfile server-cert.conf -extensions v3_req
```

## 2.2. CLIENT (CryptoClient):

### Key + CSR
```
openssl genrsa -out client.key 2048
```
```
openssl req -new -key client.key -out client.csr -subj "/C=DE/O=Client/CN=client1"
```

### Mit Root-CA signieren
```
openssl x509 -req -in client.csr -CA root_ca.crt -CAkey root_ca.key -CAcreateserial -out client.crt -days 365 -sha256
```



# 3. Keystore & Truststore erzeugen

## 3.1. SERVER (für Spring Boot: server-keystore.p12, server-truststore.p12):
```
openssl pkcs12 -export -in server.crt -inkey server.key -out server-keystore.p12 -name server -CAfile root_ca.crt -caname root -passout pass:changeit
```
```
keytool -import -trustcacerts -alias root -file root_ca.crt -keystore server-truststore.p12 -storetype PKCS12 -storepass changeit -noprompt
```

## 3.2. CLIENT (für WebClient: client-keystore.p12, client-truststore.p12):
```
openssl pkcs12 -export -in client.crt -inkey client.key -out client-keystore.p12 -name client -CAfile root_ca.crt -caname root -passout pass:changeit
```
```
keytool -import -trustcacerts -alias root -file root_ca.crt -keystore client-truststore.p12 -storetype PKCS12 -storepass changeit -noprompt
```


# 4. CryptoService TLS-Konfiguration (Spring Boot)
```
server:
port: 8443
ssl:
enabled: true
key-store: classpath:server-keystore.p12
key-store-password: changeit
trust-store: classpath:server-truststore.p12
trust-store-password: changeit
client-auth: need
```


