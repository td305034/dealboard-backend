package com.td.dealboard.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieUtils {

    @Value("${app.security.cookie-secure:false}")
    private boolean isCookieSecure;

    public ResponseCookie getCleanCookie(String name, String path) {
        return ResponseCookie.from(name, "")
                .path(path)
                .maxAge(0)
                .httpOnly(true)
                .secure(isCookieSecure)
                .sameSite("Lax")
                .build();
    }
}