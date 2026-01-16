package com.td.dealboard.auth;

public class ErrorMessages {
    // Email
    public static final String EMAIL_REQUIRED = "Email jest wymagany";
    public static final String EMAIL_INVALID = "Nieprawidłowy format adresu email";
    public static final String EMAIL_NOT_FOUND = "Nie znaleziono użytkownika o podanym adresie email";
    public static final String EMAIL_ALREADY_EXISTS = "Podany adres email jest już zajęty";

    // Password
    public static final String PASSWORD_REQUIRED = "Hasło jest wymagane";
    public static final String PASSWORD_TOO_SHORT = "Hasło musi zawierać minimum 8 znaków";
    public static final String PASSWORD_INCORRECT = "Nieprawidłowe hasło";
    public static final String PASSWORD_UPPERCASE = "Hasło musi zawierać wielką literę";
    public static final String PASSWORD_DIGIT = "Hasło musi zawierać cyfrę";
    public static final String PASSWORD_SPECIAL = "Hasło musi zawierać znak specjalny";

    //for changing password
    public static final String OLD_PASSWORD_REQUIRED = "Musisz podać stare hasło";
    public static final String OLD_PASSWORD_INVALID = "Stare hasło jest niepoprawne";

    // Name
    public static final String NAME_REQUIRED = "Imię jest wymagane";
    public static final String NAME_TOO_SHORT = "Imię musi zawierać minimum 2 znaki";

    // General
    public static final String GENERAL_ERROR = "Wystąpił nieoczekiwany błąd";
    public static final String UNAUTHORIZED = "Brak autoryzacji";

    //user role
    public static final String ROLE_REQUIRED = "Rola użytkownika jest wymagana";
}