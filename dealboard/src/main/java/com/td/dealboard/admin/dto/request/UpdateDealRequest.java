package com.td.dealboard.admin.dto.request;

import java.time.LocalDate;

public record UpdateDealRequest(
        String name,
        String store,
        String category,
        String promoNotes,
        Double priceValue,
        String priceAlt,
        Integer discountPercentage,
        String imageUrl,
        String unit,
        LocalDate validUntil,
        LocalDate validSince,
        Boolean appRequired
) {}