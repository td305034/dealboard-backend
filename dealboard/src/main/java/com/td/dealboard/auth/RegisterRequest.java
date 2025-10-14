package com.td.dealboard.auth;

import com.td.dealboard.user.Gender;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {

    @NotBlank
    private String firstName;

    @NotBlank
    private String lastName;

    @NotBlank
    @Email(message = "Must be a correct email adress")
    private String email;

    @NotBlank
    @Pattern(
            regexp = "^(?=.*[A-Z]).+$",
            message = "Password must contain at least one capital letter"
    )
    @Pattern(
            regexp = "^(?=.*\\d).+$",
            message = "Password must contain at least one number"
    )
    @Pattern(
            regexp = "^(?=.*[^A-Za-z0-9]).+$",
            message = "Password must contain at least one special sign"
    )
    private String password;

    @NotNull
    @Enumerated(EnumType.STRING)
    private Gender gender;
}
