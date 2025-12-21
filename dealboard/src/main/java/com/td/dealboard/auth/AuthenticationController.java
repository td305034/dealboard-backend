package com.td.dealboard.auth;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.td.dealboard.exceptions.ValidationException;
import com.td.dealboard.user.AuthProvider;
import com.td.dealboard.user.User;
import com.td.dealboard.user.UserRepository;
import com.td.dealboard.util.AppConstants;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static com.td.dealboard.util.AppConstants.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private final WebClient webClient;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final RestTemplate restTemplate = new RestTemplate();

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
    ) {
        String platform = redirect_uri.equals(AppConstants.APP_SCHEME.getString()) ? "mobile" : "web";

        state = platform + "|" + state;

        String googleUrl = UriComponentsBuilder.fromHttpUrl(GOOGLE_AUTH_URL.getString())
                .queryParam("client_id", GOOGLE_CLIENT_ID.getString())
                .queryParam("redirect_uri", ((platform.equals("web") ? "http://localhost:8082" : "https://judson-daydreamy-considerably.ngrok-free.dev") + GOOGLE_REDIRECT_URI.getString()))
                .queryParam("response_type", "code")
                .queryParam("scope", scope)
                .queryParam("state", state)
                .queryParam("prompt", "select_account")
                .toUriString();

        return new RedirectView(googleUrl);
    }

    @GetMapping("/callback")
    public RedirectView callback(
            @RequestParam(name = "code", required = false) String code,
            @RequestParam(name = "state", required = false) String combinedPlatformAndState
    ) {
        System.out.println("Callback received with code: " + code + " and state: " + combinedPlatformAndState);
        if (combinedPlatformAndState == null || code == null) {
            return new RedirectView(BASE_URL + "/?error=missing_code_or_state");
        }

        String[] parts = combinedPlatformAndState.split("\\|", 2);
        String platform = parts[0];
        String state = parts[1];

        String params = String.format(
                "code=%s&state=%s",
                URLEncoder.encode(code, StandardCharsets.UTF_8),
                URLEncoder.encode(state, StandardCharsets.UTF_8)
        );

        String redirectUri = platform.equals("web") ? BASE_URL.getString() : APP_SCHEME.getString();

        System.out.println(redirectUri + "?" + params);
        return new RedirectView(redirectUri + "?" + params);
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

        String tokenUrl = "https://oauth2.googleapis.com/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", AppConstants.GOOGLE_CLIENT_ID.getString());
        form.add("client_secret", AppConstants.GOOGLE_CLIENT_SECRET.getString());
        form.add("redirect_uri", (platform.equals("web") ? "http://localhost:8082" : "https://judson-daydreamy-considerably.ngrok-free.dev") + AppConstants.GOOGLE_REDIRECT_URI.getString());
        form.add("grant_type", "authorization_code");
        form.add("code", code);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);

        ResponseEntity<String> response = restTemplate.postForEntity(
                tokenUrl,
                request,
                String.class
        );

        JsonNode data;
        try {
            data = objectMapper.readTree(response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Failed to parse token response"));
        }


        try {
            SignedJWT signedJWT = SignedJWT.parse(data.get("id_token").asText());
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            Map<String, Object> userInfoWithoutExp = new HashMap<>();
            String subject = claims.getSubject();
            Object emailClaim = claims.getClaim("email");
            Object nameClaim = claims.getClaim("name");
            Object pictureClaim = claims.getClaim("picture");

            userInfoWithoutExp.put("sub", subject);
            userInfoWithoutExp.put("email", emailClaim);
            userInfoWithoutExp.put("name", nameClaim);
            userInfoWithoutExp.put("picture", pictureClaim);

            final Date issuedAt = new Date();
            final Date expiration = Date.from(Instant.now().plusSeconds(AppConstants.COOKIE_MAX_AGE.getInt()));

            User user = userRepository.findByEmail(emailClaim.toString())
                    .orElseGet(() -> {
                        User newUser = new User();
                        newUser.setEmail(emailClaim != null ? emailClaim.toString() : null);
                        newUser.setName(nameClaim != null ? nameClaim.toString() : null);
                        newUser.setProvider(AuthProvider.GOOGLE);
                        newUser.setSub(subject);
                        newUser.setPicture(pictureClaim != null ? pictureClaim.toString() : null);
                        return userRepository.save(newUser);
                    });

            String refreshToken = UUID.randomUUID().toString();
            user.setRefreshToken(refreshToken);
            user.setRefreshTokenExpiry(Date.from(Instant.now().plus(AppConstants.REFRESH_TOKEN_MAX_AGE.getInt(), ChronoUnit.SECONDS)));
            userRepository.save(user);

            String accessToken = Jwts.builder()
                    .setClaims(userInfoWithoutExp)
                    .setSubject(emailClaim.toString())
                    .setIssuedAt(issuedAt)
                    .setExpiration(expiration)
                    .signWith(Keys.hmacShaKeyFor(AppConstants.JWT_SECRET.getString().getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                    .compact();

            String[] parts = accessToken.split("\\.");

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
                        .body(Map.of("success", "true", "issuedAt", issuedAt.toString(), "expiresAt", expiration.toString()));
            }
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("accessToken", accessToken, "refreshToken", refreshToken));
        } catch (ParseException e) {
            System.err.println("Error decoding ID token: " + e.getMessage());
            return ResponseEntity.status(500).body(Map.of("error", "Failed to decode ID token"));
        }
    }

    @GetMapping("/session")
    public ResponseEntity<Map<String, Object>> getSessionInfo(
            @RequestHeader(name = "Cookie", required = false) String cookieHeader
    ) {
        if (cookieHeader == null || cookieHeader.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Not authenticated"));
        }

        Map<String, String> cookies = parseCookieHeader(cookieHeader);

        String token = cookies.get(AppConstants.COOKIE_NAME.getString());
        if (token == null || token.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Not authenticated"));
        }
        try {
            Jws<Claims> jws = Jwts.parser()
                    .setSigningKey(Keys.hmacShaKeyFor(AppConstants.JWT_SECRET.getString().getBytes(StandardCharsets.UTF_8)))
                    .build()
                    .parseClaimsJws(token);

            Claims claims = jws.getBody();

            Long cookieExpiration = null;
            if (claims.getIssuedAt() != null) {
                long iatSeconds = claims.getIssuedAt().getTime() / 1000L;
                long maxAgeSeconds = AppConstants.COOKIE_MAX_AGE.getInt();
                cookieExpiration = iatSeconds + maxAgeSeconds;
            }

            Map<String, Object> body = new HashMap<>(claims);
            body.put("cookieExpiration", cookieExpiration);

            User user = userRepository.findById(Integer.valueOf(claims.getSubject()))
                    .orElseThrow();
            body.put("onboardingCompleted", user.getOnboardingCompleted());

            return ResponseEntity.ok(body);

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

        String newAccessToken = jwtService.generateToken(user);

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

        return ResponseEntity.ok(Map.of(
                "valid", true,
                "email", user.getEmail(),
                "name", user.getName(),
                "onboardingCompleted", user.getOnboardingCompleted() != null && user.getOnboardingCompleted()

        ));
    }

    private Map<String, String> parseCookieHeader(String cookieHeader) {
        Map<String, String> map = new HashMap<>();
        String[] parts = cookieHeader.split(";");
        for (String part : parts) {
            String trimmed = part.trim();
            int eq = trimmed.indexOf('=');
            if (eq > 0) {
                String name = trimmed.substring(0, eq).trim();
                String value = trimmed.substring(eq + 1).trim();
                // Usuń ewentualne cudzysłowy
                if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
                    value = value.substring(1, value.length() - 1);
                }
                map.put(name, value);
            }
        }
        return map;
    }
}
