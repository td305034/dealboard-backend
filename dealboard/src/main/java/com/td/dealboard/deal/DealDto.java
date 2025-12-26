package com.td.dealboard.deal;

import jakarta.persistence.Column;

public record DealDto(
        Long id,
        String name,
        String store,
        String category,
        String category_code,
        Double price_value,
        String price_alt,
        String unit,
        Integer discount_percent,
        String promo_notes
) {}
