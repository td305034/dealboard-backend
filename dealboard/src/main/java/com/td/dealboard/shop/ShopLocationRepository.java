package com.td.dealboard.shop;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;

public interface ShopLocationRepository extends JpaRepository<ShopLocation, Long> {
    @Query(value = "SELECT * FROM shop_locations " +
            "WHERE ST_DWithin(location_geom, ST_MakePoint(:lon, :lat)::geography, :radiusKm * 1000)",
            nativeQuery = true)
    List<ShopLocation> findShopsWithinRadius(
            @Param("lat") double lat,
            @Param("lon") double lon,
            @Param("radiusKm") double radiusKm
    );
}