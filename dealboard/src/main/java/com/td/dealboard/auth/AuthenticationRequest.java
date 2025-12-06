package com.td.dealboard.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationRequest {
    @Schema(defaultValue = "admin@example.com")
    private String email;

    @Schema(defaultValue = "Admin123")
    private String password;
}
