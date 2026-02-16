package com.td.dealboard.admin.dto.request;

import com.td.dealboard.validation.ErrorMessages;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.LocalDate;

public record CreateDealRequest(
        @NotBlank(message = ErrorMessages.DEAL_NAME_REQUIRED)
        String name,
        @NotBlank(message = ErrorMessages.STORE_NAME_REQUIRED)
        String store,
        @NotBlank(message = ErrorMessages.CATEGORY_REQUIRED)
        String category,
        String categoryCode,
        String promoNotes,
        Double priceValue,
        String priceAlt,
        Double discountPercentage,
        String imageUrl,
        @NotBlank(message = ErrorMessages.UNIT_REQUIRED)
        String unit,
        LocalDate validUntil,
        @NotNull(message = ErrorMessages.DATE_REQUIRED)
        LocalDate validSince,
        Boolean appRequired
) {}