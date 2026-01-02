package com.td.dealboard.auth;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ChangePasswordRequest {

    @NotBlank(message = ErrorMessages.OLD_PASSWORD_REQUIRED)
    private String oldPassword;

    @NotBlank(message = ErrorMessages.PASSWORD_REQUIRED)
    @Pattern(regexp = "^(?=.*[A-Z]).+$", message = ErrorMessages.PASSWORD_UPPERCASE)
    @Pattern(regexp = "^(?=.*\\d).+$", message = ErrorMessages.PASSWORD_DIGIT)
    @Pattern(regexp = "^(?=.*[^A-Za-z0-9]).+$", message = ErrorMessages.PASSWORD_SPECIAL)
    @Size(min = 8, message = ErrorMessages.PASSWORD_TOO_SHORT)
    private String newPassword;
}
