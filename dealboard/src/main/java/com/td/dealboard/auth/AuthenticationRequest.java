package com.td.dealboard.auth;

import com.td.dealboard.validation.ErrorMessages;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
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
    @NotBlank(message = ErrorMessages.EMAIL_REQUIRED)
    @Email(message = ErrorMessages.EMAIL_INVALID)
    private String email;

    @Schema(defaultValue = "Admin123")
    @NotBlank(message = ErrorMessages.PASSWORD_REQUIRED)
    @Size(min = 8, message = ErrorMessages.PASSWORD_TOO_SHORT)
    private String password;
}
