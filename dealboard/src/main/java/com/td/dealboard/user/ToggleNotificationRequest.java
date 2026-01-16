package com.td.dealboard.user;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
public class ToggleNotificationRequest {

    @Schema(
            description = "Nazwa produktu",
            example = "Banan",
            required = true
    )
    private String productName;

    @Schema(
            description = "Czy powiadomienie ma być aktywne",
            example = "true",
            defaultValue = "true"
    )
    private Boolean active = true;
}
