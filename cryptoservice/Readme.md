curl -v -X POST https://localhost:8443/crypto/keys/generate   --cert client1.crt --key client1.key   --cacert rootCA.crt

KEYSTORE_PASSWORD=CryptoMicroservice2025! KEYSTORE_PATH=src/main/resources/keystore/keystore.jks mvn spring-boot:run


# Erstellung tls dateien:


## "openssl req -x509 -sha256 -days 3650 -newkey rsa:4096 -keyout rootCA.key -out rootCA.crt"
### Erklärung:
- req → Wir erstellen ein Zertifikat
- x509 → Das Format des Zertifikats ist X.509 (Standard)
- sha256 → Wir nutzen SHA-256 als Signaturalgorithmus
- days 3650 → Gültigkeit: 10 Jahre
- newkey rsa:4096 → Neuer Key mit 4096 Bit
- keyout rootCA.key → Private Key Datei
- out rootCA.crt → Die fertige Root-Zertifikat-Datei

### Nach dem Befehl: 
- "Country Name (2 letter code) [AU]: "
- "State or Province Name (full name) []: "
- "Locality Name (eg, city) []: "
- "Organization Name (eg, company) []: "
- "Organizational Unit Name (eg, section) []: "
- "Common Name (e.g. server FQDN or YOUR name) []: "
- "Email Address []: "

Du kannst alles leer lassen außer Common Name – gib dort z. B. Baeldung.com oder MyRootCA ein.

Wenn du zur Passworteingabe aufgefordert wirst, gib CryptoMicroservice2025! ein (wie im Tutorial angegeben).

Am Ende hast du zwei Dateien:

rootCA.crt → Das öffentliche Zertifikat

rootCA.key → Der private Schlüssel (gut sichern!)

--> Deine Root-CA steht! Du kannst sie jetzt nutzen, um andere Zertifikate zu signieren.

## "openssl req -new -newkey rsa:4096 -keyout localhost.key -out localhost.csr"

Private Key und das CSR (Anfrage zur Signierung)

Passphrase: wieder CryptoMicroservice2025! 
Common Name (CN): localhost – wichtig -> Servername
Rest wieder Enter (ignorieren)

## Konfigurationsdatei für SANs anlegen (localhost.ext)

### Inhalt: 
"                                       \
authorityKeyIdentifier=keyid,issuer     \
basicConstraints=CA:FALSE               \
subjectAltName = @alt_names

[alt_names]                             \
DNS.1 = localhost                       \
"

## "openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in localhost.csr -out localhost.crt -days 365 -CAcreateserial -extfile localhost.ext"

Server-Zertifikat signieren

Nun signieren wir die CSR (localhost.csr) mit unserer Root-CA (rootCA.crt und rootCA.key).

openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in localhost.csr -out localhost.crt -days 365 -CAcreateserial -extfile localhost.ext

## "openssl pkcs12 -export -out localhost.p12 -name "localhost" -inkey localhost.key -in localhost.crt"

Zertifikat + Key in ein PKCS12-Paket (.p12) packen

Das ist notwendig, damit wir es danach in ein Java Keystore-Format (.jks) importieren können.

Du wirst:
- Nach einem Export-Passwort gefragt → Wieder CryptoMicroservice2025! eingeben
- Und evtl. wieder das Passwort vom Private Key

## "keytool -importkeystore -srckeystore localhost.p12 -srcstoretype PKCS12 -destkeystore keystore.jks -deststoretype JKS"

Import ins Keystore (keystore.jks)

Jetzt importieren wir die .p12 Datei in ein Java KeyStore.

Du wirst nach mehreren Passwörtern gefragt:
- Source keystore password: → das, was du bei .p12 als Exportpasswort eingegeben hast -> CryptoMicroservice2025!
- Destination keystore password: → neues Passwort für keystore.jks → wieder CryptoMicroservice2025!

### Ergebnis:
Du solltest jetzt folgende Dateien haben:

localhost.key (Server-Private-Key)\
localhost.csr (Certificate Signing Request)\
localhost.crt (Signiertes Server-Zertifikat)\
localhost.ext (SAN-Konfigurationsdatei)\
localhost.p12 (PKCS12-Bundle aus Zertifikat + Key)\
keystore.jks (Java Keystore mit Server-Zertifikat)\

### Prüfung: "openssl x509 -in localhost.crt -text -noout"

Damit siehst du die ganzen Infos zum Zertifikat (CN, SAN, Gültigkeit etc.).

## Maven-Projekt aufsetzen
Falls du noch kein Spring Boot Projekt hast, kannst du eines erstellen z. B. mit https://start.spring.io:

Dependencies:

Spring Web

Spring Security

Thymeleaf

Oder manuell in der pom.xml:

```
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-thymeleaf</artifactId>
    </dependency>
</dependencies>
```

## Truststore erstellen

```
keytool -import -trustcacerts -noprompt \
  -alias ca -file rootCA.crt \
  -keystore truststore.jks \
  -storepass changeit
```

Jetzt hat dein Server ein Truststore mit deiner Root-CA.

## Client-Zertifikat erstellen

``` 
openssl req -new -newkey rsa:4096 -nodes -keyout client1.key -out client1.csr
```
Common Name (CN): Gib hier Client1 ein! (Wichtig!)

Dann signieren:
```
openssl x509 -req -CA rootCA.crt -CAkey rootCA.key \
  -in client1.csr -out client1.crt -days 365 -CAcreateserial
```

Dann packen wir es in ein .p12-Format für den Browser oder curl:
```
openssl pkcs12 -export -out client1.p12 -name "client1" \
  -inkey client1.key -in client1.crt \
  -certfile rootCA.crt
```
Passwort: CryptoMicroservice2025!

## application.properties für mTLS
```
server.ssl.key-store=store/keystore.jks
server.ssl.key-store-password=changeit
server.ssl.key-alias=localhost
server.ssl.key-password=changeit

server.ssl.trust-store=store/truststore.jks
server.ssl.trust-store-password=changeit
server.ssl.client-auth=need

server.port=8443
```

## Spring Security für X.509 konfigurieren
siehe SecurityConfig.java

## curl mit Zertifikat testen
Du hast .crt und .key:
```
curl -v -k \
  --cert client1.crt \
  --key client1.key \
  https://localhost:8443/crypto/keys/generate
```
