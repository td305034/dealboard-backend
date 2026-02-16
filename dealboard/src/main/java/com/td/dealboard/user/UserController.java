package com.td.dealboard.user;

import com.td.dealboard.user.dto.NotificationTimeDto;
import com.td.dealboard.user.dto.request.PushTokenRequest;
import com.td.dealboard.user.dto.request.ToggleNotificationRequest;
import com.td.dealboard.user.dto.TrackedProductsDto;
import com.td.dealboard.user.dto.TrackedStoresDto;
import com.td.dealboard.user.dto.response.AccessTokenResponse;
import com.td.dealboard.user.enums.NotificationTime;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
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
    public ResponseEntity<AccessTokenResponse> changeName(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestBody String name) {
        String accessToken = userService.changeName(userDetails.getUsername(), name);
        return ResponseEntity.ok(new AccessTokenResponse(accessToken));
    }

    @PutMapping("/notification-time")
    public ResponseEntity<Void> updateNotificationTime(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody NotificationTimeDto req
    ) {
        userService.changeNotificationTime(userDetails.getUsername(), req);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/notification-time")
    public ResponseEntity<NotificationTimeDto> getNotificationTime(@AuthenticationPrincipal UserDetails userDetails) {
        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));
        NotificationTime time = user.getNotificationTime();
        return ResponseEntity.ok(new NotificationTimeDto(time));
    }
}
