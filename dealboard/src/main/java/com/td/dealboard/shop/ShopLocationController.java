package com.td.dealboard.shop;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/shops")
@RequiredArgsConstructor
public class ShopLocationController {

    private final ShopLocationRepository shopLocationRepository;

    @GetMapping("/nearby")
    public List<ShopLocation> getNearbyShops(
            @RequestParam double lat,
            @RequestParam double lon,
            @RequestParam double radiusKm
    ) {
        return shopLocationRepository.findShopsWithinRadius(lat, lon, radiusKm);
    }

    @GetMapping("/nearby/unique")
    public List<String> getNearbyUniqueStores(
            @RequestParam double lat,
            @RequestParam double lon,
            @RequestParam double radiusKm
    ) {
        return shopLocationRepository.findShopsWithinRadius(lat, lon, radiusKm)
                .stream()
                .map(ShopLocation::getStoreName)
                .distinct()
                .toList();
    }
}
