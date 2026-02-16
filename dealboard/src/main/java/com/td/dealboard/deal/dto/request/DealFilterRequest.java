package com.td.dealboard.deal.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;

public record DealFilterRequest(
        @Schema(example = "Kawa")
        String name,

        @Schema(example = "Biedronka")
        String storeName,

        @Schema(defaultValue = "Napoje")
        String category,

        @Schema(defaultValue = "0.0")
        Double minPrice,

        @Schema(defaultValue = "1000.0")
        Double maxPrice
) { }