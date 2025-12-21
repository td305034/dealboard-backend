package com.td.dealboard.user;

import com.td.dealboard.deal.DealRepository;
import com.td.dealboard.deal.DealService;
import org.apache.coyote.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private DealService dealService;

    @PostMapping("/tracked-products")
    public ResponseEntity<?> updateTrackedProducts(
            @AuthenticationPrincipal User user,
            @RequestBody Set<String> products
    ) {
        user.setTrackedProducts(products);
        user.setOnboardingCompleted(true);
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

    @GetMapping("/onboarding-status")
    public boolean isOnboardingCompleted(
            @AuthenticationPrincipal User user
    ){
        return user.getOnboardingCompleted();
    }
}
