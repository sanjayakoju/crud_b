package com.cruddemo;

import com.cruddemo.config.AppProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
//@EnableJpaAuditing(auditorAwareRef = "auditorAwareUserImpl")
@EnableConfigurationProperties(AppProperties.class)
public class CrudDemoBApplication {

    @Value("${spring.web.resources.static-locations}")
    static String name;

    public static void main(String[] args) {
        System.out.println("name :" +name);
        SpringApplication.run(CrudDemoBApplication.class, args);
    }

}
