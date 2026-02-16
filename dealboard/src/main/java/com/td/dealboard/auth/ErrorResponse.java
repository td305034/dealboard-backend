package com.td.dealboard.auth;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Map;

@Builder
public record ErrorResponse(
        @JsonInclude(JsonInclude.Include.NON_NULL)
        Map<String, String> fieldErrors,
        String message,
        int status,
        LocalDateTime timestamp
){}