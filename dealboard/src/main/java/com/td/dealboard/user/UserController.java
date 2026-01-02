package com.td.dealboard.user;

import com.td.dealboard.auth.AuthenticationService;
import com.td.dealboard.auth.JwtService;
import com.td.dealboard.deal.DealRepository;
import com.td.dealboard.deal.DealService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.Response;
import org.checkerframework.checker.units.qual.A;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {
    private final UserRepository userRepository;
    private final DealService dealService;
    private final JwtService jwtService;
    private final AuthenticationService authenticationService;
    private final UserService userService;

    @PostMapping("/tracked-products")
    public ResponseEntity<?> updateTrackedProducts(
            @AuthenticationPrincipal User user,
            @RequestBody(required = false) Set<String> products
    ) {
        if (user == null) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "error", "UNAUTHORIZED",
                            "message", "User is not authenticated"
                    ));
        }
        if (products == null) {
            return ResponseEntity
                    .badRequest()
                    .body(Map.of(
                            "error", "INVALID_REQUEST",
                            "message", "Request body is required"
                    ));
        }
        if (products.isEmpty()) {
            return ResponseEntity
                    .badRequest()
                    .body(Map.of(
                            "error", "EMPTY_PRODUCTS",
                            "message", "Products list cannot be empty"
                    ));
        }
        boolean hasInvalid = products.stream()
                .anyMatch(p -> p == null || p.isBlank());

        if (hasInvalid) {
            return ResponseEntity
                    .badRequest()
                    .body(Map.of(
                            "error", "INVALID_PRODUCT",
                            "message", "Product names cannot be empty"
                    ));
        }

        user.setTrackedProducts(products);
        userRepository.save(user);

        return ResponseEntity.ok(
                Map.of(
                        "success", true,
                        "count", products.size()
                )
        );
    }

    @PostMapping("/selected-stores")
    public ResponseEntity<?> saveSelectedStores(
            @AuthenticationPrincipal User user,
            @RequestBody List<String> stores
    ) {
        user.setSelectedStores(new HashSet<>(stores));
        userRepository.save(user);

        return ResponseEntity.ok(Map.of("success", true, "count", stores.size()));
    }

    @PostMapping("/complete-onboarding")
    public ResponseEntity<?> completeOnboarding(
            @AuthenticationPrincipal User user
    ) {
        user.setOnboardingCompleted(true);
        userRepository.save(user);

        Map<String, Object> userInfoWithoutExp = authenticationService.createUserInfoWithoutExp(user);

        String accessToken = jwtService.generateToken(userInfoWithoutExp, user);
        return ResponseEntity.ok(Map.of("accessToken", accessToken));
    }

    @PostMapping("/register-push-token")
    public ResponseEntity<?> registerPushToken(
            @AuthenticationPrincipal User user,
            @RequestBody Map<String, String> body) {
        String token = body.get("token");
        if (token == null || token.isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        userService.addPushToken(user.getEmail(), token);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/unregister-push-token")
    public ResponseEntity<?> unregisterPushToken(
            @AuthenticationPrincipal User user,
            @RequestBody Map<String, String> body) {
        String token = body.get("token");
        if (token == null || token.isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        userService.removePushToken(user.getEmail(), token);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/toggle-notification")
    public ResponseEntity<?> addNotification(
            @AuthenticationPrincipal User user,
            @RequestBody Map<String, String> body) {
        if (user.getNotifications() == null) {
            user.setNotifications(new HashMap<>());
        }
        String email = user.getEmail();
        String productName = body.get("productName");
        Boolean active = Boolean.valueOf(body.get("active"));
        if(productName == null || productName.isBlank()) {
            return ResponseEntity
                    .badRequest()
                    .body(Map.of(
                            "error", "INVALID_PRODUCT",
                            "message", "Product name cannot be empty"
                    ));
        }

        return ResponseEntity.ok(userService.toggleNotification(email, productName, active));
    }
}
