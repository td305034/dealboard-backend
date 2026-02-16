package com.td.dealboard.auth;

import com.td.dealboard.validation.ErrorMessages;
import com.td.dealboard.validation.StrongPassword;
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

    @StrongPassword
    private String newPassword;
}
