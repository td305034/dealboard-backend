package com.td.dealboard.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.td.dealboard.user.enums.NotificationTime;
import com.td.dealboard.validation.ErrorMessages;
import com.td.dealboard.user.enums.AuthProvider;
import com.td.dealboard.user.enums.Role;
import com.td.dealboard.user.User;
import com.td.dealboard.user.UserRepository;
import com.td.dealboard.util.AppConstants;
import com.td.dealboard.validation.ValidationException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static com.td.dealboard.util.AppConstants.*;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final WebClient webClient;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest req){
        String email = req.email().toLowerCase();
        Map<String, String> errors = new HashMap<>();
        if(userRepository.findByEmail(email).isPresent()){;
            errors.put("email", ErrorMessages.EMAIL_NOT_FOUND);
            throw new ValidationException(errors);
        }

        User user = User.builder()
                .name(req.name())
                .email(email)
                .password(passwordEncoder.encode(req.password()))
                .role(Role.USER)
                .provider(AuthProvider.LOCAL)
                .onboardingCompleted(false)
                .notificationTime(NotificationTime.MORNING)
                .build();
        userRepository.save(user);
        Map<String, Object> userInfoWithoutExp = createUserInfoWithoutExp(user);

        String jwtToken = jwtService.generateToken(userInfoWithoutExp, user);
        String refreshToken = UUID.randomUUID().toString();

        user.setRefreshToken(refreshToken);
        user.setRefreshTokenExpiry(Date.from(Instant.now().plus(AppConstants.REFRESH_TOKEN_MAX_AGE.getInt(), ChronoUnit.SECONDS)));
        userRepository.save(user);

        return AuthenticationResponse.builder()
                .accessToken((jwtToken))
                .refreshToken((refreshToken))
                .build();
    }
    public void changePassword(String email, ChangePasswordRequest req) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("User with email " + email + " not found"));

        if (!passwordEncoder.matches(req.getOldPassword(), user.getPassword())) {
            throw new ValidationException(Map.of("oldPassword", ErrorMessages.OLD_PASSWORD_INVALID));
        }

        user.setPassword(passwordEncoder.encode(req.getNewPassword()));
        userRepository.save(user);
    }
    public AuthenticationResponse authenticate(AuthenticationRequest req){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        req.getEmail(),
                        req.getPassword()
                )
        );
        User user = userRepository.findByEmail(req.getEmail())
                .orElseThrow();
        Map<String, Object> userInfoWithoutExp = createUserInfoWithoutExp(user);
        String refreshToken = UUID.randomUUID().toString();
        user.setRefreshToken(refreshToken);
        user.setRefreshTokenExpiry(Date.from(Instant.now().plus(AppConstants.REFRESH_TOKEN_MAX_AGE.getInt(), ChronoUnit.SECONDS)));
        userRepository.save(user);
        String jwtToken = jwtService.generateToken(userInfoWithoutExp, user);
        return AuthenticationResponse.builder()
                .accessToken((jwtToken))
                .refreshToken(refreshToken)
                .build();
    }

    public Mono<GoogleTokenResponse> exchangeCodeForTokens(String code) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("code", code);
        formData.add("client_id", GOOGLE_CLIENT_ID.getString());
        formData.add("client_secret", GOOGLE_CLIENT_SECRET.getString());
        formData.add("redirect_uri", GOOGLE_REDIRECT_URI.getString());
        formData.add("grant_type", "authorization_code");

        return webClient.post()
                .uri("/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue(formData)
                .retrieve()
                .bodyToMono(GoogleTokenResponse.class);
    }


    public boolean userExists(String email) {

        return userRepository.findByEmail(email).isPresent();
    }

    public boolean isPasswordCorrect(String email, String password) {
        User user = userRepository.findByEmail(email).orElseThrow();
        return passwordEncoder.matches(password, user.getPassword());
    }

    public Map<String, Object> createUserInfoWithoutExp(User user) {
        Map<String, Object> userInfoWithoutExp = new HashMap<>();
        userInfoWithoutExp.put("sub", user.getEmail());
        userInfoWithoutExp.put("email", user.getEmail());
        userInfoWithoutExp.put("name", user.getName());
        userInfoWithoutExp.put("picture", user.getPicture());
        userInfoWithoutExp.put("provider", user.getProvider());
        userInfoWithoutExp.put("onboardingCompleted", user.getOnboardingCompleted());
        userInfoWithoutExp.put("role", user.getRole().name());
        System.out.println(user.getRole().name());
        return userInfoWithoutExp;
    }

    public String createGoogleUrl(String redirect_uri, String scope, String state) {
        String platform = redirect_uri.equals(AppConstants.APP_SCHEME.getString()) ? "mobile" : "web";

        state = platform + "|" + state;

        return UriComponentsBuilder.fromHttpUrl(GOOGLE_AUTH_URL.getString())
                .queryParam("client_id", GOOGLE_CLIENT_ID.getString())
                .queryParam("redirect_uri", ((platform.equals("web") ? "http://localhost:8082" : "https://judson-daydreamy-considerably.ngrok-free.dev") + GOOGLE_REDIRECT_URI.getString()))
                .queryParam("response_type", "code")
                .queryParam("scope", scope)
                .queryParam("state", state)
                .queryParam("prompt", "select_account")
                .toUriString();
    }

    public String createRedirectUriWithParams(String code, String combinedPlatformAndState) {
        String[] parts = combinedPlatformAndState.split("\\|", 2);
        String platform = parts[0];
        String state = parts[1];

        String params = String.format(
                "code=%s&state=%s",
                URLEncoder.encode(code, StandardCharsets.UTF_8),
                URLEncoder.encode(state, StandardCharsets.UTF_8)
        );

        String redirectUri = platform.equals("web") ? BASE_URL.getString() : APP_SCHEME.getString();

        return redirectUri + "?" + params;
    }

    public User googleLoginCreateUser(JsonNode data) throws ParseException{
        SignedJWT signedJWT = SignedJWT.parse(data.get("id_token").asText());
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        String subject = claims.getSubject();
        Object emailClaim = claims.getClaim("email");
        Object nameClaim = claims.getClaim("name");
        Object pictureClaim = claims.getClaim("picture");

        return userRepository.findByEmail(emailClaim.toString())
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setEmail(emailClaim != null ? emailClaim.toString() : null);
                    newUser.setName(nameClaim != null ? nameClaim.toString() : null);
                    newUser.setProvider(AuthProvider.GOOGLE);
                    newUser.setSub(subject);
                    newUser.setPicture(pictureClaim != null ? pictureClaim.toString() : null);
                    newUser.setOnboardingCompleted(false);
                    return userRepository.save(newUser);
                });
    }

    public String createAccessToken(User user){

        Map<String, Object> userInfoWithoutExp = createUserInfoWithoutExp(user);

        final Date issuedAt = new Date();
        final Date expiration = Date.from(Instant.now().plusSeconds(AppConstants.COOKIE_MAX_AGE.getInt()));

        return Jwts.builder()
                .setClaims(userInfoWithoutExp)
                .setSubject(userInfoWithoutExp.get("email").toString())
                .setIssuedAt(issuedAt)
                .setExpiration(expiration)
                .signWith(Keys.hmacShaKeyFor(AppConstants.JWT_SECRET.getString().getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();
    }

    public String createRefreshToken(User user){
        String refreshToken = UUID.randomUUID().toString();
        user.setRefreshToken(refreshToken);
        user.setRefreshTokenExpiry(Date.from(Instant.now().plus(AppConstants.REFRESH_TOKEN_MAX_AGE.getInt(), ChronoUnit.SECONDS)));
        userRepository.save(user);
        return refreshToken;
    }

    public ResponseEntity<String> initTokenResponse(String platform, String code) {
        String redirectUri = (platform.equals("web")
                ? "http://localhost:8082"
                : "https://judson-daydreamy-considerably.ngrok-free.dev")
                + AppConstants.GOOGLE_REDIRECT_URI.getString();

        String tokenUrl = "https://oauth2.googleapis.com/token";

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", AppConstants.GOOGLE_CLIENT_ID.getString());
        form.add("client_secret", AppConstants.GOOGLE_CLIENT_SECRET.getString());
        form.add("redirect_uri", redirectUri);
        form.add("grant_type", "authorization_code");
        form.add("code", code);


        String responseBody = webClient.post()
                .uri("https://oauth2.googleapis.com/token") // pełny URL
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue(form)
                .retrieve()
                .bodyToMono(String.class)
                .block();

        return ResponseEntity.ok(responseBody);
    }

    public Map<String, Object> retrieveSession(String token) {
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
        return body;
    }

    public Map<String, String> parseCookieHeader(String cookieHeader) {
        Map<String, String> map = new HashMap<>();
        String[] parts = cookieHeader.split(";");
        for (String part : parts) {
            String trimmed = part.trim();
            int eq = trimmed.indexOf('=');
            if (eq > 0) {
                String name = trimmed.substring(0, eq).trim();
                String value = trimmed.substring(eq + 1).trim();
                if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
                    value = value.substring(1, value.length() - 1);
                }
                map.put(name, value);
            }
        }
        return map;
    }
}
