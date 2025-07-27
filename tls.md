Schritt-für-Schritt: Root CA erzeugen mit OpenSSL

1. Root Key erzeugen

openssl genrsa -out root_ca.key 4096

2. Root-Zertifikat (self-signed) erstellen

openssl req -x509 -new -nodes \
-key root_ca.key \
-sha256 -days 3650 \
-out root_ca.crt

Du wirst nach Details gefragt wie:

Country Name (2 letter code): DE
State or Province: Baden-Württemberg
Locality Name: Wangen
Organization Name: MyCryptoCA
Organizational Unit: DevCA
Common Name: InternalCA
Email Address: ca@example.com
