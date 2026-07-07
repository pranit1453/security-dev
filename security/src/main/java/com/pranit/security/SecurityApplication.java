package com.pranit.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class SecurityApplication {

    static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }

}
