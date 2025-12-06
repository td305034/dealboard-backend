package com.td.dealboard;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class DealboardApplication {

	public static void main(String[] args) {
		SpringApplication.run(DealboardApplication.class, args);
	}

}
