package com.example.dataingestor;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class})
public class DataingestorApplication {

	public static void main(String[] args) {
		SpringApplication.run(DataingestorApplication.class, args);
	}

}
