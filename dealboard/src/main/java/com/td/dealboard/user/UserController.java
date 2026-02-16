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
    private final UserService userService;

    @PostMapping("/selected-products")
    public ResponseEntity<Void> updateTrackedProducts(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid  @RequestBody TrackedProductsDto req
    ) {
        userService.updateTrackedProducts(userDetails.getUsername(), req);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/selected-stores")
    public ResponseEntity<Void> saveSelectedStores(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody TrackedStoresDto req
    ) {
        userService.updateTrackedStores(userDetails.getUsername(), req);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/selected-products")
    public ResponseEntity<TrackedProductsDto> getSelectedProducts(@AuthenticationPrincipal UserDetails userDetails) {
        Set<String> products = userService.getSelectedProducts(userDetails.getUsername());
        return ResponseEntity.ok(new TrackedProductsDto(products));
    }

    @GetMapping("/selected-stores")
    public ResponseEntity<TrackedStoresDto> getSelectedStores(@AuthenticationPrincipal UserDetails userDetails) {
        Set<String> stores = userService.getSelectedStores(userDetails.getUsername());
        return ResponseEntity.ok(new TrackedStoresDto(stores));
    }

    @PostMapping("/complete-onboarding")
    public ResponseEntity<AccessTokenResponse> completeOnboarding(
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        String jwtToken = userService.completeOnboarding(userDetails.getUsername());
        return ResponseEntity.ok(new AccessTokenResponse(jwtToken));
    }

    @PostMapping("/register-push-token")
    public ResponseEntity<Void> registerPushToken(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody PushTokenRequest req) {
        userService.addPushToken(userDetails.getUsername(), req);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/unregister-push-token")
    public ResponseEntity<Void> unregisterPushToken(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody PushTokenRequest req) {
        userService.removePushToken(userDetails.getUsername(), req);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/toggle-notification")
    public ResponseEntity<Void> addNotification(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody ToggleNotificationRequest req) {
        userService.toggleNotification(userDetails.getUsername(), req);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/change-name")
    public ResponseEntity<?> changeName(
            @AuthenticationPrincipal User user,
            @RequestBody Map<String, String> body) {
        String email = user.getEmail();
        String accessToken = userService.changeName(email, body.get("name"));
        return ResponseEntity.ok(Map.of("accessToken", accessToken));
    }
}
