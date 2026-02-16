package com.td.dealboard.admin.dto.request;

import com.td.dealboard.user.enums.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;

public record UpdateUserRequest(
        String name,
        @Email
        String email,
        @NotNull
        Role role
) {}