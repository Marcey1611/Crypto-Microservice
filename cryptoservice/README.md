curl -v -X POST https://localhost:8443/crypto/keys/generate   --cert client1.crt --key client1.key   --cacert server.crt

curl -X POST https://localhost:8443/crypto/jwt/generate   --cert client1.crt --key client1.key --cacert rootCA.crt   \-H "Content-Type: application/json"   \-d '{"issuedTo": "Client1"}'

curl -X POST https://localhost:8443/crypto/encrypt   --cert client1.crt --key client1.key --cacert rootCA.crt   \-H "Content-Type: application/json"   \-d '{"plainText": "Hallo Welt!","jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJDcnlwdG9NaWNyb3NlcnZpY2VBY2Nlc1Rva2VuIiwia2V5QWxpYXMiOiJocDRqenZ5b2MxdmZ6cnZtbnJianV3IiwiaXNzdWVkVG8iOiJDbGllbnQxIiwiaWF0IjoxNzQ1NDIzNDcyLCJleHAiOjE3NDU0MjcwNzJ9.-MVUlz5LuF5j09BH16CKt07VLEb5VC6oJkHgFFdtN10"}'

curl -X POST https://localhost:8443/crypto/decrypt   --cert client1.crt --key client1.key --cacert rootCA.crt   \-H "Content-Type: application/json"   \-d '{"cipherText": "eAxGHodzwWlN2LyqDS0iblkihBkyPPGRCn0V","jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJDcnlwdG9NaWNyb3NlcnZpY2VBY2Nlc1Rva2VuIiwia2V5QWxpYXMiOiJocDRqenZ5b2MxdmZ6cnZtbnJianV3IiwiaXNzdWVkVG8iOiJDbGllbnQxIiwiaWF0IjoxNzQ1NDIzNDcyLCJleHAiOjE3NDU0MjcwNzJ9.-MVUlz5LuF5j09BH16CKt07VLEb5VC6oJkHgFFdtN10"}'


Linux:
```
MASTER_KEYSTORE_PASSWORD=PzDXe4in3qG7LWvSgwLp0JG3Snm7UxT5kFVuG1ey3h7hyp9IVL MASTER_KEYSTORE_PATH=src/main/resources/keystore/master-keystore.p12 CLIENT_KEYSTORE_PASSWORD=P095NxN4cROz0IaWF8105KB6oVYNXKg2q4JqhSKf6zMawsT2Lr CLIENT_KEYSTORE_PATH=src/main/resources/keystore/client-keystore.p12 mvn spring-boot:run
```

Powershell (windows):
```
$env:MASTER_KEYSTORE_PASSWORD = "PzDXe4in3qG7LWvSgwLp0JG3Snm7UxT5kFVuG1ey3h7hyp9IVL"
$env:MASTER_KEYSTORE_PATH = "src/main/resources/keystore/master-keystore.p12"
$env:CLIENT_KEYSTORE_PASSWORD = "P095NxN4cROz0IaWF8105KB6oVYNXKg2q4JqhSKf6zMawsT2Lr"
$env:CLIENT_KEYSTORE_PATH = "src/main/resources/keystore/client-keystore.p12"
mvn spring-boot:run
```



curl -v -X POST https://localhost:8443/crypto/keys/generate \
--cert cryptoclient/src/main/resources/tls/client1.crt \
--key cryptoclient/src/main/resources/tls/client1.key \
--cacert ca/root-ca.crt



curl -v -X POST https://localhost:8443/crypto/jwt/generate \
--cert cryptoclient/src/main/resources/tls/client1.crt \
--key cryptoclient/src/main/resources/tls/client1.key \
--cacert ca/root-ca.crt \
-H "Content-Type: application/json" \
-d '{"issuedTo": "Client2"}'




curl -v -X POST https://localhost:8443/crypto/encrypt \
--cert cryptoclient/src/main/resources/tls/client1.crt \
--key cryptoclient/src/main/resources/tls/client1.key \
--cacert ca/root-ca.crt \
-H "Content-Type: application/json" \
-d '{
"plainText": "Hallo Welt!",
"jwt": "JWT_TOKEN_HERE"
}'





curl -v -X POST https://localhost:8443/crypto/decrypt \
--cert cryptoclient/src/main/resources/tls/client2.crt \
--key cryptoclient/src/main/resources/tls/client2.key \
--cacert ca/root-ca.crt \
-H "Content-Type: application/json" \
-d '{
"cipherText": "CIPHER_TEXT_HERE",
"jwt": "JWT_TOKEN_HERE"
}'
