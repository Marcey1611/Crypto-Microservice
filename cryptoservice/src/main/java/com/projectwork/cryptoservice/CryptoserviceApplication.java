package com.projectwork.cryptoservice;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Application Class
 * 
 * @author Marcel Eichelberger
 */
@SpringBootApplication
@EnableScheduling
public class CryptoserviceApplication {

	private static final Logger LOGGER = LoggerFactory.getLogger(CryptoserviceApplication.class);

	/**
	 * Main method to start the application.
	 *
	 * @param args command line arguments
	 */
	public static void main(final String[] args) {
		LOGGER.info("Starting CryptoService Application...");
		SpringApplication.run(CryptoserviceApplication.class, args);
	}
}