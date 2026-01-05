package com.td.dealboard.data;

import com.td.dealboard.shop.ShopLocationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
@RequiredArgsConstructor
public class ShopLocationInitializer implements CommandLineRunner {

    private final JdbcTemplate jdbcTemplate;
    private final ShopLocationRepository shopLocationRepository;

    @Override
    public void run(String... args) {

        if (shopLocationRepository.count() > 0) {
            return;
        }

        jdbcTemplate.execute("""
            INSERT INTO shop_locations (store_name, location_geom)
            SELECT DISTINCT
                UPPER(s.name),
                ST_Transform(p.way, 4326)::geography
            FROM osm.planet_osm_point p
            JOIN stores s
              ON UPPER(p.name) LIKE '%' || UPPER(s.name) || '%'
            WHERE p.name IS NOT NULL
              AND (
                    p.shop IS NOT NULL
                 OR p.building IN ('retail', 'commercial', 'supermarket')
              );
        """);

        jdbcTemplate.execute("""
            INSERT INTO shop_locations (store_name, location_geom)
            SELECT DISTINCT
                UPPER(s.name),
                ST_Centroid(ST_Transform(p.way, 4326))::geography
            FROM osm.planet_osm_polygon p
            JOIN stores s
              ON UPPER(p.name) LIKE '%' || UPPER(s.name) || '%'
            WHERE p.name IS NOT NULL
              AND (
                    p.shop IS NOT NULL
                 OR p.building IN ('retail', 'commercial', 'supermarket')
              );
        """);
    }
}
