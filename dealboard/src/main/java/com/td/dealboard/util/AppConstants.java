package com.td.dealboard.util;
import java.util.HashMap;
import java.util.Map;

public enum AppConstants {

    // Authentication
    TOKEN_KEY_NAME("accessToken"),
    COOKIE_NAME("auth_token"),
    REFRESH_COOKIE_NAME("refresh_token"),
    COOKIE_MAX_AGE(20), // seconds
    JWT_EXPIRATION_TIME("20s"),
    REFRESH_TOKEN_EXPIRY("30d"),
    REFRESH_TOKEN_MAX_AGE(30 * 24 * 60 * 60), // 30 days in seconds
    REFRESH_BEFORE_EXPIRY_SEC(60), // 1 minute before expiry

    // Google OAuth
    GOOGLE_CLIENT_ID(System.getenv("GOOGLE_CLIENT_ID")),
    GOOGLE_CLIENT_SECRET(System.getenv("GOOGLE_CLIENT_SECRET")),
    GOOGLE_REDIRECT_URI("/api/auth/callback"),
    GOOGLE_AUTH_URL("https://accounts.google.com/o/oauth2/v2/auth"),

    // Apple OAuth
    APPLE_CLIENT_ID("com.beto.expoauthexample.web"),
    APPLE_CLIENT_SECRET(System.getenv("APPLE_CLIENT_SECRET")),
    APPLE_REDIRECT_URI((System.getenv("EXPO_PUBLIC_BASE_URL") != null ? System.getenv("EXPO_PUBLIC_BASE_URL") : "http://localhost:3000") + "/api/auth/apple/callback"),
    APPLE_AUTH_URL("https://appleid.apple.com/auth/authorize"),

    // Environment
    BASE_URL(System.getenv("EXPO_PUBLIC_BASE_URL")),
    APP_SCHEME(System.getenv("EXPO_PUBLIC_SCHEME")),
    JWT_SECRET(System.getenv("JWT_SECRET")),
    SECRET_KEY(System.getenv("SECRET"));

    private final Object value;

    AppConstants(Object value) {
        this.value = value;
    }

    public String getString() {
        return value != null ? value.toString() : null;
    }

    public Integer getInt() {
        return value instanceof Integer ? (Integer) value : null;
    }
}
