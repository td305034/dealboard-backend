package com.td.dealboard.deal;

import jakarta.persistence.Column;

public record DealDto(
        String name,
        String category,
        String category_code,
        String price_raw,
        Double price_value,
        String price_alt,
        String unit,
        Integer discount_percent,
        String promo_notes
) {}
