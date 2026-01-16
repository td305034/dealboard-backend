package com.td.dealboard.admin;

import com.td.dealboard.auth.ErrorMessages;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record CreateUserRequest(
        @NotBlank(message = ErrorMessages.NAME_REQUIRED)
        String name,

        @NotBlank(message = ErrorMessages.EMAIL_REQUIRED)
        @Email(message = ErrorMessages.EMAIL_INVALID)
        String email,

        @NotBlank(message = ErrorMessages.PASSWORD_REQUIRED)
        @Pattern(regexp = "^(?=.*[A-Z]).+$", message = ErrorMessages.PASSWORD_UPPERCASE)
        @Pattern(regexp = "^(?=.*\\d).+$", message = ErrorMessages.PASSWORD_DIGIT)
        @Pattern(regexp = "^(?=.*[^A-Za-z0-9]).+$", message = ErrorMessages.PASSWORD_SPECIAL)
        @Size(min = 8, message = ErrorMessages.PASSWORD_TOO_SHORT)
        String password,

        @NotBlank(message = ErrorMessages.ROLE_REQUIRED)
        String role
) {}
