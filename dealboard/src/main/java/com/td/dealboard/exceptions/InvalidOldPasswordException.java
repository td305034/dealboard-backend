package com.td.dealboard.exceptions;

import com.td.dealboard.auth.ErrorMessages;

import java.util.Map;

public class InvalidOldPasswordException extends ValidationException {

    public InvalidOldPasswordException() {
        super(Map.of(
                "oldPassword", ErrorMessages.OLD_PASSWORD_INVALID
        ));
    }
}
