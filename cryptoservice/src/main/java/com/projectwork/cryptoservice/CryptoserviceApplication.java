package com.projectwork.cryptoservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Application Class
 * 
 * @author Marcel Eichelberger
 * 
 * TODO: Logging
 * TODO: Error handling
 * 
 */

@SpringBootApplication
@ComponentScan(basePackages = "com.projectwork.cryptoservice")
@EnableScheduling
public class CryptoserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(CryptoserviceApplication.class, args);
	}

}

/**
 * SecureCodingPractices later implementation:
 * - OWASP [107] In catch-Blöcken keine Stacktraces direkt loggen -> später generische Fehler-Response + Logging verbessern
 * - OWASP [131] Least Privilege: Sicherstellen, dass der Service nur mit nötigen Dateisystem-Rechten läuft (kein root)
 * - OWASP [105] Prüfen, ob du ein FIPS 140-2 konformes JCE (Java Cryptography Extension) nutzt -> gut für Doku
 * - OWASP [142] Datei- und Zugriffsrechte auf den Keystore beschränken (nur les- und schreibbar für Service-User)
 * - OWASP [143] Später TLS -> Communication Security sicherstellen
 */

// Vllt interessant bzgl mtls: https://github.com/making/demo-mtls/tree/main/src/main/resources/self-signed