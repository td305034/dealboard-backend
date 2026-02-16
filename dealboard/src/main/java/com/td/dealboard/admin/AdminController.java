package com.td.dealboard.admin;

import com.td.dealboard.admin.dto.AdminUserDto;
import com.td.dealboard.admin.dto.request.CreateDealRequest;
import com.td.dealboard.admin.dto.request.CreateUserRequest;
import com.td.dealboard.admin.dto.request.UpdateDealRequest;
import com.td.dealboard.admin.dto.request.UpdateUserRequest;
import com.td.dealboard.deal.DealDto;
import com.td.dealboard.deal.DealService;
import com.td.dealboard.deal.dto.request.DealFilterRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
@RequiredArgsConstructor
public class AdminController {
    private final AdminService adminService;
    private final DealService dealService;

    @GetMapping("/users")
    public ResponseEntity<Page<AdminUserDto>> getAllUsers(
            @RequestParam(defaultValue = "") String search,
            @RequestParam(defaultValue = "0") int page
    ) {
        Pageable pageable = PageRequest.of(page, 10, Sort.by("id").descending());
        return ResponseEntity.ok(adminService.findAllUsers(search, pageable));
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<AdminUserDto> getUserById(@PathVariable Integer id) {
        return ResponseEntity.ok(adminService.findUserById(id));
    }

    @PostMapping("/users")
    public ResponseEntity<Void> createUser(@Valid @RequestBody CreateUserRequest req) {
        adminService.createUser(req);
        return ResponseEntity.ok().build();
    }

    @PutMapping("/users/{id}")
    public ResponseEntity<Void> updateUser(@PathVariable Integer id, @Valid @RequestBody UpdateUserRequest req) {
        adminService.updateUser(id, req);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/users/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Integer id) {
        adminService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/deals")
    public ResponseEntity<Page<DealDto>> getAllDeals(
            @AuthenticationPrincipal UserDetails userDetails,
            @ParameterObject DealFilterRequest req,
            @RequestParam(defaultValue = "0") int page
    ) {
        Pageable pageable = PageRequest.of(page, 10, Sort.by("id").descending());
        return ResponseEntity.ok(dealService.getAllDealsWithFilters(userDetails.getUsername(), req, pageable));
    }


    @GetMapping("/deals/{id}")
    public ResponseEntity<DealDto> getDealById(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.findDealById(id));
    }

    @PostMapping("/deals")
    public ResponseEntity<Void> createDeal(@Valid @RequestBody CreateDealRequest req) {
        adminService.createDeal(req);
        return ResponseEntity.ok().build();
    }

    @PutMapping("/deals/{id}")
    public ResponseEntity<DealDto> updateDeal(@PathVariable Long id, @Valid @RequestBody UpdateDealRequest req) {
        adminService.updateDeal(id, req);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/deals/{id}")
    public ResponseEntity<Void> deleteDeal(@PathVariable Long id) {
        adminService.deleteDeal(id);
        return ResponseEntity.noContent().build();
    }
}