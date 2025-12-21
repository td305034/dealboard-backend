package com.td.dealboard.auth;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

import java.util.HashMap;
import java.util.Map;

@Data
@RequiredArgsConstructor
public class ErrorResponse {
    private Map<String, String> fieldErrors = new HashMap<>();
    private String message;
    private int status;

    public ErrorResponse(String message, int status) {
        this.message = message;
        this.status = status;
    }

    public void addFieldError(String field, String error) {
        this.fieldErrors.put(field, error);
    }
}