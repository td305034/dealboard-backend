package com.td.dealboard.user;

import com.td.dealboard.auth.AuthenticationService;
import com.td.dealboard.auth.JwtService;
import com.td.dealboard.deal.DealRepository;
import com.td.dealboard.deal.DealService;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {
    private UserRepository userRepository;
    private DealService dealService;
    private JwtService jwtService;
    private AuthenticationService authenticationService;

    @PostMapping("/tracked-products")
    public ResponseEntity<?> updateTrackedProducts(
            @AuthenticationPrincipal User user,
            @RequestBody Set<String> products
    ) {
        System.out.println("/TRACKED-PRODUCTS: " + user.getId());
        System.out.println("User ID: " + user.getId());
        System.out.println("User email: " + user.getEmail());
        user.setTrackedProducts(products);
        userRepository.save(user);
        return ResponseEntity.ok(Map.of("success", true, "count", products.size()));
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

}
