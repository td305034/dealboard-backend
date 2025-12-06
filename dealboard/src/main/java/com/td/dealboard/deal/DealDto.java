package com.td.dealboard.deal;

public record DealDto(
        String name,
        String description,
        String category,
        String price_raw,
        Double price_value,
        String unit,
        Integer discount_percent,
        String promo_notes,
        Integer page
) {}
