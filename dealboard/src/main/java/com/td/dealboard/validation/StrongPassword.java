package com.td.dealboard.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = {})
@NotBlank
@Pattern(regexp = "^(?=.*[A-Z]).+$", message = ErrorMessages.PASSWORD_UPPERCASE)
@Pattern(regexp = "^(?=.*\\d).+$", message = ErrorMessages.PASSWORD_DIGIT)
@Pattern(regexp = "^(?=.*[^A-Za-z0-9]).+$", message = ErrorMessages.PASSWORD_SPECIAL)
@Size(min = 8, message = ErrorMessages.PASSWORD_TOO_SHORT)
public @interface StrongPassword {
    String message() default "Słabe hasło";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}