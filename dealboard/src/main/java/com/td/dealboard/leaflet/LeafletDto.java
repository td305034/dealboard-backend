package com.td.dealboard.leaflet;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.LocalDate;
import java.util.List;

public record LeafletDto(
        @JsonProperty("shopName") String storeName,
        @JsonProperty("leafletLink") String leafletLink,
        @JsonProperty("imageUrl") String imageUrl,
        @JsonProperty("validUntil") String validUntil,
        @JsonProperty("leafletsURL") List<String> leafletsURL,
        @JsonProperty("downloadDate") LocalDate downloadDate
) {}