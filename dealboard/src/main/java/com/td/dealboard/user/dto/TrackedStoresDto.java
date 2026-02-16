package com.td.dealboard.user.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.Set;

public record TrackedStoresDto(
        @NotNull
        @NotEmpty
        Set<String> trackedStores
) { }
