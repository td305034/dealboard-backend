package com.td.dealboard.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class CategoriesConfig {

    Logger log = LoggerFactory.getLogger(CategoriesConfig.class);

    @Value("${app.categories.path}")
    private String categoriesPath;

    @Bean
    public Map<String, String> categoriesMap() {
        Map<String, String> map = new HashMap<>();

        ClassPathResource resource = new ClassPathResource(categoriesPath);
        if (!resource.exists()) {
            log.warn("Categories file not found: {}", categoriesPath);
            return map;
        }

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {

            reader.lines()
                    .filter(line -> !line.isBlank())
                    .forEach(line -> {
                        String[] parts = line.split(";", 2);
                        String code = parts[0].trim();
                        String label = parts.length > 1 ? parts[1].trim() : code;
                        map.put(code, label);
                    });

        } catch (IOException e) {
            log.error("Failed to read categories file", e);
        }
        return map;
    }
}
