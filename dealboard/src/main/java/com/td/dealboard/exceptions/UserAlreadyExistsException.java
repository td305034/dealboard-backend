package com.td.dealboard.exceptions;

public class UserAlreadyExistsException extends RuntimeException {
    public UserAlreadyExistsException(String email) {
        super("User with an email " + email + " already exists.");
    }
}
