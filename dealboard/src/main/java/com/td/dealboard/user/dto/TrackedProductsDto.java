package com.td.dealboard.user.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.Set;

public record TrackedProductsDto(
        @NotNull
        @NotEmpty
        Set<String> trackedProducts
) { }
