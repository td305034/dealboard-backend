package com.td.dealboard.validation;

import java.util.HashMap;
import java.util.Map;

public class ValidationException extends RuntimeException {
  private Map<String, String> fieldErrors = new HashMap<>();

  public ValidationException(String message) {
    super(message);
  }

  public ValidationException(Map<String, String> fieldErrors) {
    super("Validation failed");
    this.fieldErrors = fieldErrors;
  }

  public Map<String, String> getFieldErrors() {
    return fieldErrors;
  }

  public void addFieldError(String field, String error) {
    this.fieldErrors.put(field, error);
  }
}
