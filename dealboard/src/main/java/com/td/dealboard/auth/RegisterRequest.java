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
public class RegisterRequest {

    @NotBlank(message = ErrorMessages.NAME_REQUIRED)
    @Size(min = 2, message = ErrorMessages.NAME_TOO_SHORT)
    private String name;

    @NotBlank(message = ErrorMessages.EMAIL_REQUIRED)
    @Email(message = ErrorMessages.EMAIL_INVALID)
    private String email;

    @NotBlank(message = ErrorMessages.PASSWORD_REQUIRED)
    @Pattern(
            regexp = "^(?=.*[A-Z]).+$",
            message = ErrorMessages.PASSWORD_UPPERCASE
    )
    @Pattern(
            regexp = "^(?=.*\\d).+$",
            message = ErrorMessages.PASSWORD_DIGIT
    )
    @Pattern(
            regexp = "^(?=.*[^A-Za-z0-9]).+$",
            message = ErrorMessages.PASSWORD_SPECIAL
    )
    @Size(min = 8, message = ErrorMessages.PASSWORD_TOO_SHORT)
    private String password;
}
