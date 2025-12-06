package com.td.dealboard.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.td.dealboard.user.AuthProvider;
import com.td.dealboard.user.User;
import com.td.dealboard.user.UserRepository;
import com.td.dealboard.util.AppConstants;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static com.td.dealboard.util.AppConstants.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private final WebClient webClient;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final RestTemplate restTemplate = new RestTemplate();

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @Valid @RequestBody RegisterRequest request
    ){
        System.out.println("Received registration request for email: " + request.getEmail());
        return ResponseEntity.ok(authenticationService.register(request));
    }
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ){
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

        System.out.println(request.getBody());
        System.out.println(request.getHeaders());
        ResponseEntity<String> response = restTemplate.postForEntity(
                tokenUrl,
                request,
                String.class
        );

        JsonNode data;
        try {
            data = objectMapper.readTree(response.getBody());
            System.out.println("Response JSON: " + data.toPrettyString());
        } catch (Exception e) {
            System.err.println("Error parsing response: " + e.getMessage());
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

            userRepository.findByEmail(emailClaim.toString())
                    .orElseGet(() -> {
                        User newUser = new User();
                        newUser.setEmail(emailClaim != null ? emailClaim.toString() : null);
                        newUser.setName(nameClaim != null ? nameClaim.toString() : null);
                        newUser.setProvider(AuthProvider.GOOGLE);
                        newUser.setSub(subject);
                        newUser.setPicture(pictureClaim != null ? pictureClaim.toString() : null);
                        return userRepository.save(newUser);
                    });

            String accessToken = Jwts.builder()
                    .setClaims(userInfoWithoutExp)
                    .setSubject(claims.getSubject())
                    .setIssuedAt(issuedAt)
                    .setExpiration(expiration)
                    .signWith(Keys.hmacShaKeyFor(AppConstants.JWT_SECRET.getString().getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                    .compact();

            String[] parts = accessToken.split("\\.");

            if(platform.equals("web")){
                ResponseCookie cookie = ResponseCookie.from(AppConstants.COOKIE_NAME.getString(), accessToken)
                        .httpOnly(true)
                        .secure(false) // ustaw true dla HTTPS
                        .path("/")
                        .maxAge(AppConstants.COOKIE_MAX_AGE.getInt())
                        .sameSite("Lax")
                        .build();

                return ResponseEntity.ok()
                        .header(HttpHeaders.SET_COOKIE, cookie.toString())
                        .body(Map.of("success", "true", "issuedAt", issuedAt.toString(), "expiresAt", expiration.toString()));
            }
            return ResponseEntity.ok(Map.of("accessToken", accessToken));
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
            SignedJWT signedJWT = SignedJWT.parse(token);
            boolean valid = signedJWT.verify(new MACVerifier(AppConstants.JWT_SECRET.getString().getBytes(StandardCharsets.UTF_8)));
            if (!valid) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Invalid token"));
            }

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            Long cookieExpiration = null;

            if (claims.getIssueTime() != null) {
                long iatSeconds = claims.getIssueTime().getTime() / 1000L;
                long maxAgeSeconds = AppConstants.COOKIE_MAX_AGE.getInt();
                cookieExpiration = Long.valueOf(iatSeconds + maxAgeSeconds);
            }

            Map<String, Object> body = new HashMap<>(claims.getClaims());
            body.put("cookieExpiration", cookieExpiration);

            return ResponseEntity.ok(body);

        } catch (ParseException | JOSEException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Invalid token"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Server error"));
        }


    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout() {
        // Stwórz ciasteczko access z Max-Age=0 aby je usunąć
        ResponseCookie accessCookie = ResponseCookie.from(AppConstants.COOKIE_NAME.getString(), "")
                .path("/")
                .maxAge(0)
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .build();

        // Stwórz ciasteczko refresh z Max-Age=0 aby je usunąć
        ResponseCookie refreshCookie = ResponseCookie.from(AppConstants.REFRESH_COOKIE_NAME.getString(), "")
                .path("/")
                .maxAge(0)
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .build();

        HttpHeaders headers = new HttpHeaders();
        // Dodaj oba nagłówki Set-Cookie (dwa satelitarne ciasteczka)
        headers.add(HttpHeaders.SET_COOKIE, accessCookie.toString());
        headers.add(HttpHeaders.SET_COOKIE, refreshCookie.toString());

        return new ResponseEntity<>(Map.of("success", true), headers, HttpStatus.OK);
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
