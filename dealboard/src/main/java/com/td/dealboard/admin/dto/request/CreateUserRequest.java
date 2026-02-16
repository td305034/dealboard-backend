package com.td.dealboard.admin.dto.request;

import com.td.dealboard.validation.ErrorMessages;
import com.td.dealboard.user.enums.Role;
import com.td.dealboard.validation.StrongPassword;
import jakarta.validation.constraints.*;

public record CreateUserRequest(
        @NotBlank(message = ErrorMessages.NAME_REQUIRED)
        String name,

        @NotBlank(message = ErrorMessages.EMAIL_REQUIRED)
        @Email(message = ErrorMessages.EMAIL_INVALID)
        String email,

        @StrongPassword
        String password,

        @NotNull(message = ErrorMessages.ROLE_REQUIRED)
        Role role
) {}
