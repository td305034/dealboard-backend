package com.td.dealboard.auth;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.td.dealboard.exceptions.ValidationException;
import com.td.dealboard.user.User;
import com.td.dealboard.user.UserRepository;
import com.td.dealboard.util.AppConstants;
import io.jsonwebtoken.*;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import java.text.ParseException;
import java.util.*;

import static com.td.dealboard.util.AppConstants.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final JwtService jwtService;
    private final UserRepository userRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @Valid @RequestBody RegisterRequest request
    ){
        Map<String, String> errors = new HashMap<>();

        if (authenticationService.emailExists(request.getEmail())) {
            errors.put("email", ErrorMessages.EMAIL_ALREADY_EXISTS);
            throw new ValidationException(errors);
        }

        if (!errors.isEmpty()) {
            throw new ValidationException(errors);
        }

        return ResponseEntity.ok(authenticationService.register(request));
    }
    @PostMapping("/change-password")
    public ResponseEntity<String> changePassword(
            @AuthenticationPrincipal User currentUser,
            @Valid @RequestBody ChangePasswordRequest request
    ) {
        authenticationService.changePassword(currentUser, request);
        return ResponseEntity.ok("Password changed successfully");
    }
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @Valid @RequestBody AuthenticationRequest request
    ){
        Map<String, String> errors = new HashMap<>();

        if (!authenticationService.userExists(request.getEmail())) {
            errors.put("email", ErrorMessages.EMAIL_NOT_FOUND);
            throw new ValidationException(errors);
        }

        if (!authenticationService.isPasswordCorrect(request.getEmail(), request.getPassword())) {
            errors.put("password", ErrorMessages.PASSWORD_INCORRECT);
            throw new ValidationException(errors);
        }

        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @GetMapping("/authorize")
    public RedirectView authorize(@RequestParam String redirect_uri,
                                  @RequestParam String scope,
                                  @RequestParam(required = false) String state
    ) {;
        return new RedirectView(authenticationService.createGoogleUrl(redirect_uri, scope, state));
    }

    @GetMapping("/callback")
    public RedirectView callback(
            @RequestParam(name = "code", required = false) String code,
            @RequestParam(name = "state", required = false) String combinedPlatformAndState
    ) {
        if (combinedPlatformAndState == null || code == null) {
            return new RedirectView(BASE_URL + "/?error=missing_code_or_state");
        }

        return new RedirectView(authenticationService.createRedirectUriWithParams(code, combinedPlatformAndState));
    }

    @PostMapping(value = "/token", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String, String>> exchangeCode(
            @RequestParam("code") String code,
            @RequestParam(value = "platform", required = false, defaultValue = "native") String platform
    ) {
        if (code == null || code.isBlank()) {
            Map<String, String> err = Map.of("error", "Missing auth code");
            return ResponseEntity.badRequest().body(err);
        }

        String accessToken;
        String refreshToken;

        ResponseEntity<String> response = authenticationService.initTokenResponse(platform, code);

        JsonNode data;
        try {
            data = objectMapper.readTree(response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Failed to parse token response"));
        }


        try {
            User user = authenticationService.googleLoginCreateUser(data);
            accessToken = authenticationService.createAccessToken(user);
            refreshToken = authenticationService.createRefreshToken(user);
        } catch (ParseException e) {
            System.err.println("Error decoding ID token: " + e.getMessage());
            return ResponseEntity.status(500).body(Map.of("error", "Failed to decode ID token"));
        }
        if(platform.equals("web")){
            ResponseCookie accessCookie = ResponseCookie.from(AppConstants.COOKIE_NAME.getString(), accessToken)
                    .httpOnly(true)
                    .secure(false)
                    .path("/")
                    .maxAge(AppConstants.COOKIE_MAX_AGE.getInt())
                    .sameSite("Lax")
                    .build();

            ResponseCookie refreshCookie = ResponseCookie.from(AppConstants.REFRESH_COOKIE_NAME.getString(), refreshToken)
                    .httpOnly(true)
                    .secure(true) // true dla HTTPS
                    .path("/api/auth/auth/refresh") // endpoint do refresh token
                    .maxAge(AppConstants.REFRESH_TOKEN_MAX_AGE.getInt())
                    .sameSite("Strict")
                    .build();


            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, accessCookie.toString())
                    .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                    .body(Map.of("success", "true"));
        }
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("accessToken", accessToken, "refreshToken", refreshToken));

    }

    @GetMapping("/session")
    public ResponseEntity<Map<String, Object>> getSessionInfo(
            @RequestHeader(name = "Cookie", required = false) String cookieHeader
    ) {
        if (cookieHeader == null || cookieHeader.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Not authenticated"));
        }

        Map<String, String> cookies = authenticationService.parseCookieHeader(cookieHeader);
        String token = cookies.get(AppConstants.COOKIE_NAME.getString());

        if (token == null || token.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Not authenticated"));
        }

        try {
            return ResponseEntity.ok(authenticationService.retrieveSession(token));
        } catch (ExpiredJwtException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Token expired"));
        } catch (SignatureException | MalformedJwtException | UnsupportedJwtException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Invalid token"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Server error"));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refreshToken(
            @CookieValue(name = "refreshToken", required = false) String refreshTokenCookie,
            @RequestBody(required = false) Map<String, String> body
    ) {
        String refreshToken = refreshTokenCookie;
        if ((refreshToken == null || refreshToken.isBlank()) && body != null) {
            refreshToken = body.get("refreshToken");
        }

        if (refreshToken == null || refreshToken.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "No refresh token provided"));
        }

        User user = userRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        if (user.getRefreshTokenExpiry() == null || user.getRefreshTokenExpiry().before(new Date())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Refresh token expired"));
        }

        Map<String, Object> userInfoWithoutExp = authenticationService.createUserInfoWithoutExp(user);

        String newAccessToken = jwtService.generateToken(userInfoWithoutExp, user);

        return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
    }



    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout() {
        ResponseCookie accessCookie = ResponseCookie.from(AppConstants.COOKIE_NAME.getString(), "")
                .path("/")
                .maxAge(0)
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .build();

        ResponseCookie refreshCookie = ResponseCookie.from(AppConstants.REFRESH_COOKIE_NAME.getString(), "")
                .path("/api/auth/refresh")
                .maxAge(0)
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .build();

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.SET_COOKIE, accessCookie.toString());
        headers.add(HttpHeaders.SET_COOKIE, refreshCookie.toString());

        return new ResponseEntity<>(Map.of("success", true), headers, HttpStatus.OK);
    }

    @GetMapping("/verify")
    public ResponseEntity<?> verifyToken(@AuthenticationPrincipal UserDetails userDetails) {
        if (userDetails == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid token"));
        }

        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElse(null);

        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "User not found"));
        }

        Map<String, Object> response = new HashMap<>();
        response.put("valid", true);
        response.put("email", user.getEmail());
        response.put("name", user.getName() != null ? user.getName() : "");
        response.put("role", user.getRole() != null ? user.getRole().name() : "USER");
        response.put("onboardingCompleted", user.getOnboardingCompleted() != null && user.getOnboardingCompleted());

        return ResponseEntity.ok(response);
    }
}
