package com.td.dealboard.admin;

import com.td.dealboard.deal.Deal;
import com.td.dealboard.deal.DealDto;
import com.td.dealboard.deal.DealRepository;
import com.td.dealboard.store.StoreRepository;
import com.td.dealboard.user.AuthProvider;
import com.td.dealboard.user.User;
import com.td.dealboard.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
@RequiredArgsConstructor
public class AdminController {
    private final UserRepository userRepository;
    private final DealRepository dealRepository;
    private final StoreRepository storeRepository;

    private final PasswordEncoder passwordEncoder;

    @GetMapping("/users")
    public List<AdminUserDto> getAllUsers() {
        return userRepository.findAll().stream()
                .map(u -> new AdminUserDto(
                        u.getId().longValue(),
                        u.getName(),
                        u.getEmail(),
                        u.getRole().name(),
                        u.getCreatedAt()
                ))
                .collect(Collectors.toList());
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<AdminUserDto> getUserById(@PathVariable Integer id) {
        return userRepository.findById(id)
                .map(u -> ResponseEntity.ok(new AdminUserDto(
                        u.getId().longValue(),
                        u.getName(),
                        u.getEmail(),
                        u.getRole().name(),
                        u.getCreatedAt()
                )))
                .orElse(ResponseEntity.notFound().build());
    }

    public record UpdateUserRequest(String name, String email, String role) {}

    @PostMapping("/users")
    public ResponseEntity<AdminUserDto> createUser(@RequestBody CreateUserRequest req) {
        if (req.email() == null || req.email().isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        User user = User.builder()
                .email(req.email())
                .password(passwordEncoder.encode(req.password()))
                .name(req.name())
                .role(req.role() == null ? null : Enum.valueOf(com.td.dealboard.user.Role.class, req.role()))
                .provider(AuthProvider.LOCAL)
                .onboardingCompleted(false)
                .build();
        userRepository.save(user);
        AdminUserDto dto = new AdminUserDto(user.getId().longValue(), user.getName(), user.getEmail(), user.getRole().name(), user.getCreatedAt());
        return ResponseEntity.status(HttpStatus.CREATED).body(dto);
    }

    @PutMapping("/users/{id}")
    public ResponseEntity<AdminUserDto> updateUser(@PathVariable Integer id, @RequestBody UpdateUserRequest req) {
        return userRepository.findById(id).map(u -> {
            if (req.name != null) u.setName(req.name);
            if (req.email != null) u.setEmail(req.email);
            if (req.role != null) u.setRole(Enum.valueOf(com.td.dealboard.user.Role.class, req.role));
            userRepository.save(u);
            return ResponseEntity.ok(new AdminUserDto(u.getId().longValue(), u.getName(), u.getEmail(), u.getRole().name(), u.getCreatedAt()));
        }).orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/users/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Integer id) {
        return userRepository.findById(id).map(u -> {
            userRepository.delete(u);
            return ResponseEntity.noContent().<Void>build();
        }).orElse(ResponseEntity.notFound().build());
    }

    // ============= DEALS =============
    @GetMapping("/deals")
    public List<AdminDealDto> getAllDeals() {
        return dealRepository.findAll().stream()
                .map(d -> new AdminDealDto(
                        d.getId(),
                        d.getName(),
                        d.getStore() != null ? d.getStore().getName() : null,
                        d.getCategory(),
                        d.getPromoNotes(),
                        d.getPriceValue(),
                        d.getPriceAlt(),
                        d.getDiscountPercentage() != null ? d.getDiscountPercentage().doubleValue() : null,
                        null,
                        d.getUnit(),
                        d.getValidUntil() != null ? d.getValidUntil().toString() : null,
                        d.getValidSince() != null ? d.getValidSince().toString() : null,
                        d.getAppRequired()
                ))
                .collect(Collectors.toList());
    }

    @GetMapping("/deals/{id}")
    public ResponseEntity<AdminDealDto> getDealById(@PathVariable Long id) {
        return dealRepository.findById(id.intValue())
                .map(d -> ResponseEntity.ok(new AdminDealDto(
                        d.getId(),
                        d.getName(),
                        d.getStore() != null ? d.getStore().getName() : null,
                        d.getCategory(),
                        d.getPromoNotes(),
                        d.getPriceValue(),
                        d.getPriceAlt(),
                        d.getDiscountPercentage() != null ? d.getDiscountPercentage().doubleValue() : null,
                        null,
                        d.getUnit(),
                        d.getValidUntil() != null ? d.getValidUntil().toString() : null,
                        d.getValidSince() != null ? d.getValidSince().toString() : null,
                        d.getAppRequired()
                )))
                .orElse(ResponseEntity.notFound().build());
    }

    public record CreateDealRequest(
            String name,
            String store,
            String category,
            String promoNotes,
            Double priceValue,
            String priceAlt,
            Double discountPercentage,
            String imageUrl,
            String unit,
            String validUntil,
            String validSince,
            Boolean appRequired
    ) {}

    @PostMapping("/deals")
    public ResponseEntity<AdminDealDto> createDeal(@RequestBody CreateDealRequest req) {
        if (req.name == null || req.store == null || req.category == null || req.unit == null || req.validUntil == null) {
            return ResponseEntity.badRequest().build();
        }

        var store = storeRepository.findByName(req.store).orElse(null);
        if (store == null) return ResponseEntity.badRequest().build();

        LocalDate validSinceDate;
        LocalDate validUntilDate;
        try {
            validSinceDate = LocalDate.parse(req.validSince);
            validUntilDate = LocalDate.parse(req.validUntil);
        } catch (DateTimeParseException e) {
            return ResponseEntity.badRequest().build();
        }

        Deal deal = Deal.builder()
                .name(req.name)
                .store(store)
                .category(req.category)
                .categoryCode(req.category)
                .promoNotes(req.promoNotes)
                .priceValue(req.priceValue)
                .priceAlt(req.priceAlt)
                .discountPercentage(req.discountPercentage != null ? req.discountPercentage.intValue() : null)
                .unit(req.unit)
                .validSince(validSinceDate)
                .validUntil(validUntilDate)
                .appRequired(req.appRequired != null ? req.appRequired : false)
                .build();

        dealRepository.save(deal);

        AdminDealDto dto = new AdminDealDto(deal.getId(),
                deal.getName(),
                deal.getStore().getName(),
                deal.getCategory(),
                deal.getPromoNotes(),
                deal.getPriceValue(),
                deal.getPriceAlt(),
                deal.getDiscountPercentage() != null ? deal.getDiscountPercentage().doubleValue() : null,
                null,
                deal.getUnit(),
                deal.getValidUntil().toString(),
                deal.getValidSince().toString(),
                deal.getAppRequired());
        return ResponseEntity.status(HttpStatus.CREATED).body(dto);
    }

    public record UpdateDealRequest(
            String name,
            String store,
            String category,
            String promoNotes,
            Double priceValue,
            String priceAlt,
            Double discountPercentage,
            String imageUrl,
            String unit,
            String validUntil
    ) {}

    @PutMapping("/deals/{id}")
    public ResponseEntity<AdminDealDto> updateDeal(@PathVariable Long id, @RequestBody UpdateDealRequest req) {
        return (ResponseEntity<AdminDealDto>) dealRepository.findById(id.intValue()).map(d -> {
            if (req.name != null) d.setName(req.name);
            if (req.store != null) {
                var s = storeRepository.findByName(req.store).orElse(null);
                if (s == null) return ResponseEntity.badRequest().build();
                d.setStore(s);
            }
            if (req.category != null) d.setCategory(req.category);
            if (req.promoNotes != null) d.setPromoNotes(req.promoNotes);
            if (req.priceValue != null) d.setPriceValue(req.priceValue);
            if (req.priceAlt != null) d.setPriceAlt(req.priceAlt);
            if (req.discountPercentage != null) d.setDiscountPercentage(req.discountPercentage.intValue());
            if (req.unit != null) d.setUnit(req.unit);
            if (req.validUntil != null) {
                try {
                    d.setValidUntil(LocalDate.parse(req.validUntil));
                } catch (DateTimeParseException e) {
                    return ResponseEntity.badRequest().build();
                }
            }
            dealRepository.save(d);
            AdminDealDto dto = new AdminDealDto(
                    d.getId(),
                    d.getName(),
                    d.getStore().getName(),
                    d.getCategory(),
                    d.getPromoNotes(),
                    d.getPriceValue(),
                    d.getPriceAlt(),
                    d.getDiscountPercentage() != null ? d.getDiscountPercentage().doubleValue() : null,
                    null, d.getUnit(), d.getValidUntil() != null ? d.getValidUntil().toString() : null,
                    d.getValidSince() != null ? d.getValidSince().toString() : null,
                    d.getAppRequired());
            return ResponseEntity.ok(dto);
        }).orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/deals/{id}")
    public ResponseEntity<Void> deleteDeal(@PathVariable Long id) {
        return dealRepository.findById(id.intValue()).map(d -> {
            dealRepository.delete(d);
            return ResponseEntity.noContent().<Void>build();
        }).orElse(ResponseEntity.notFound().build());
    }
}