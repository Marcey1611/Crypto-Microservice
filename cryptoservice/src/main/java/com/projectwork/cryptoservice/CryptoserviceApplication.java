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

