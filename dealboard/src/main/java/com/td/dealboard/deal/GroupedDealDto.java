package com.td.dealboard.deal;

public record GroupedDealDto(
        String keyword,
        DealDto deal,
        boolean isPrimary,
        boolean isCheapest
) {}
