package com.projectwork.cryptoservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = "com.projectwork.cryptoservice")
public class CryptoserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(CryptoserviceApplication.class, args);
	}

}
