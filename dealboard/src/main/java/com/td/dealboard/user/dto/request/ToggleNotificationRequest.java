package com.td.dealboard.user.dto.request;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;

public record ToggleNotificationRequest(
    @Schema(
            description = "Nazwa produktu",
            example = "Banan",
            required = true
    )
    @NotNull
    String productName,

    @Schema(
            description = "Czy powiadomienie ma być aktywne",
            example = "true",
            defaultValue = "true"
    )
    Boolean active
){}
