# CryptoClient

mvn spring-boot:run -Dspring-boot.run.arguments="--client.name=client1 --client.port=8081 --client.password=changeit --otherclient.host=localhost --otherclient.port=8082 --client.crypto-service-url=https://localhost:8443/crypto"

mvn spring-boot:run -Dspring-boot.run.arguments="--client.name=client2 --client.port=8082 --client.password=changeit --otherclient.host=localhost --otherclient.port=8081 --client.crypto-service-url=https://localhost:8443/crypto"
