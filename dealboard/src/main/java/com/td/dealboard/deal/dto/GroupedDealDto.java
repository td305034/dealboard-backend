package com.td.dealboard.deal.dto;

import com.td.dealboard.deal.DealDto;

public record GroupedDealDto(
        String keyword,
        DealDto deal,
        boolean isPrimary,
        boolean isCheapest
) {}
