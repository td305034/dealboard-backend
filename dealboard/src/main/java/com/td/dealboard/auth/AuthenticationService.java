package com.td.dealboard.auth;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.td.dealboard.exceptions.UserAlreadyExistsException;
import com.td.dealboard.user.AuthProvider;
import com.td.dealboard.user.Role;
import com.td.dealboard.user.User;
import com.td.dealboard.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.text.ParseException;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static com.td.dealboard.util.AppConstants.*;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private Map<String, Boolean> validStates = new ConcurrentHashMap<>();

    public AuthenticationResponse register(RegisterRequest request){
        String email = request.getEmail();
        if (userRepository.existsByEmail(email)) {
            throw new UserAlreadyExistsException(email);
        }

        User user = User.builder()
                .name(request.getName())
                .email(email)
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .provider(AuthProvider.LOCAL)
                .build();
        userRepository.save(user);
        String jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .accessToken((jwtToken))
                .build();
    }
    public AuthenticationResponse authenticate(AuthenticationRequest request){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();
        String jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .accessToken((jwtToken))
                .build();
    }

    public GoogleTokenResponse exchangeCodeForTokens(String code) {
        RestTemplate restTemplate = new RestTemplate();

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("code", code);
        params.add("client_id", GOOGLE_CLIENT_ID.getString());
        params.add("client_secret", GOOGLE_CLIENT_SECRET.getString());
        params.add("redirect_uri", GOOGLE_REDIRECT_URI.getString());
        params.add("grant_type", "authorization_code");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> request =
                new HttpEntity<>(params, headers);

        ResponseEntity<GoogleTokenResponse> response = restTemplate.postForEntity(
                "https://oauth2.googleapis.com/token",
                request,
                GoogleTokenResponse.class
        );

        return response.getBody();
    }

    public String createJwtFromGoogleIdToken(String idToken) throws ParseException, JOSEException {
        // 1) sparsuj id_token Google (nie zakładamy tu automatycznej weryfikacji podpisu)
        SignedJWT googleJwt = SignedJWT.parse(idToken);
        JWTClaimsSet googleClaims = googleJwt.getJWTClaimsSet();

        // Pobierz pola które chcesz przepisać do własnego tokenu
        String subject = googleClaims.getSubject(); // sub
        String email = (String) googleClaims.getClaim("email");
        String name = (String) googleClaims.getClaim("name");
        String picture = (String) googleClaims.getClaim("picture");

        // 2) zbuduj claims dla własnego JWT
        Date issuedAt = new Date();
        Date expiration = new Date(issuedAt.getTime() + JWT_EXPIRATION_TIME.getInt() * 1000);

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .subject(subject)
                .issueTime(issuedAt)
                .expirationTime(expiration)
                // możesz dodać custom claims
                .claim("email", email)
                .claim("name", name)
                .claim("picture", picture)
                .claim("provider", "google");

        JWTClaimsSet jwtClaims = builder.build();

        // 3) podpisz token HS256 przy użyciu sekretu (Text -> bytes)
        // Uwaga: sekret powinien mieć odpowiednią entropię (minimum 256 bitów dla HS256)
        byte[] secretBytes = JWT_SECRET.getString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        JWSSigner signer = new MACSigner(secretBytes);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JWT)
                .build();

        SignedJWT signedJWT = new SignedJWT(header, jwtClaims);
        signedJWT.sign(signer);

        // 4) zwróć serializowany token
        return signedJWT.serialize();
    }


    public String generateState() {
        String state = UUID.randomUUID().toString();
        validStates.put(state, true);
        return state;
    }

    public boolean verifyState(String state) {
        return validStates.remove(state) != null;
    }
}
