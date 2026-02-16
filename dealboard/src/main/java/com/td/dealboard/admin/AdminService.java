package com.td.dealboard.admin;

import com.td.dealboard.admin.dto.AdminUserDto;
import com.td.dealboard.admin.dto.request.CreateDealRequest;
import com.td.dealboard.admin.dto.request.CreateUserRequest;
import com.td.dealboard.admin.dto.request.UpdateDealRequest;
import com.td.dealboard.admin.dto.request.UpdateUserRequest;
import com.td.dealboard.deal.Deal;
import com.td.dealboard.deal.DealDto;
import com.td.dealboard.deal.DealRepository;
import com.td.dealboard.store.Store;
import com.td.dealboard.store.StoreRepository;
import com.td.dealboard.user.enums.AuthProvider;
import com.td.dealboard.user.User;
import com.td.dealboard.user.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Service
@RequiredArgsConstructor
public class AdminService {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final DealRepository dealRepository;
    private final StoreRepository storeRepository;

    @Transactional(readOnly = true)
    public Page<AdminUserDto> findAllUsers(String keyword, Pageable pageable) {
        return userRepository.findByKeyword(keyword, pageable)
                .map(u -> new AdminUserDto(
                        u.getId().longValue(),
                        u.getName(),
                        u.getEmail(),
                        u.getRole().name(),
                        u.getCreatedAt()
                ));
    }

    @Transactional(readOnly = true)
    public AdminUserDto findUserById(Integer id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User with id " + id + " not found"));
        return new AdminUserDto(
                user.getId().longValue(),
                user.getName(),
                user.getEmail(),
                user.getRole().name(),
                user.getCreatedAt()
        );
    }

    @Transactional
    public void createUser(CreateUserRequest req) {
        User user = User.builder()
                .email(req.email())
                .password(passwordEncoder.encode(req.password()))
                .name(req.name())
                .role(req.role())
                .provider(AuthProvider.LOCAL)
                .onboardingCompleted(false)
                .build();
        userRepository.save(user);
    }

    @Transactional
    public void updateUser(Integer id, UpdateUserRequest req) {
        User user = userRepository.findById(id).orElseThrow(() -> new EntityNotFoundException("User with id " + id + " not found"));
        user.setName(req.name());
        user.setEmail(req.email());
        user.setRole(req.role());
        userRepository.save(user);
    }

    @Transactional
    public void deleteUser(Integer id) {
        User user = userRepository.findById(id).orElseThrow(()->new EntityNotFoundException("User with id " + id + " not found"));
        userRepository.delete(user);
    }


    @Transactional(readOnly = true)
    public DealDto findDealById(Long id) {
        Deal deal = dealRepository.findById(id.intValue()).orElseThrow(() -> new EntityNotFoundException("Deal with id " + id + " not found"));
        return new DealDto(
                deal.getId(),
                deal.getName(),
                deal.getStore() != null ? deal.getStore().getName() : null,
                deal.getCategory(),
                deal.getCategoryCode(),
                deal.getPriceValue(),
                deal.getPriceAlt(),
                deal.getUnit(),
                deal.getDiscountPercentage(),
                deal.getPromoNotes(),
                deal.getValidUntil(),
                null,
                deal.getAppRequired());
    }

    @Transactional
    public void createDeal( CreateDealRequest req) {
        Store store = storeRepository.findByName(req.store()).orElseThrow(()->new EntityNotFoundException("Store with name " + req.store() + " not found"));

        Deal deal = Deal.builder()
                .name(req.name())
                .store(store)
                .category(req.category())
                .categoryCode(req.categoryCode())
                .promoNotes(req.promoNotes())
                .priceValue(req.priceValue())
                .priceAlt(req.priceAlt())
                .discountPercentage(req.discountPercentage() != null ? req.discountPercentage().intValue() : null)
                .unit(req.unit())
                .validSince(req.validSince())
                .validUntil(req.validUntil())
                .appRequired(req.appRequired() != null ? req.appRequired() : false)
                .build();

        dealRepository.save(deal);
    }

    @Transactional
    public void updateDeal(Long id, UpdateDealRequest req) {
        Deal deal = dealRepository.findById(id.intValue())
                .orElseThrow(() -> new EntityNotFoundException("Deal with id " + id + " not found"));

        if (req.name() != null) deal.setName(req.name());

        if (req.store() != null) {
            Store store = storeRepository.findByName(req.store())
                    .orElseThrow(() -> new EntityNotFoundException("Store with name " + req.store() + " not found"));
            deal.setStore(store);
        }

        if (req.category() != null) deal.setCategory(req.category());
        if (req.promoNotes() != null) deal.setPromoNotes(req.promoNotes());
        if (req.priceValue() != null) deal.setPriceValue(req.priceValue());
        if (req.priceAlt() != null) deal.setPriceAlt(req.priceAlt());
        if (req.discountPercentage() != null) deal.setDiscountPercentage(req.discountPercentage());
        if (req.unit() != null) deal.setUnit(req.unit());
        if (req.validUntil() != null) deal.setValidUntil(req.validUntil());
        if (req.validSince() != null) deal.setValidUntil(req.validSince());
        if (req.appRequired() != null) deal.setAppRequired(req.appRequired());

        dealRepository.save(deal);
    }

    @Transactional
    public void deleteDeal(Long id) {
        Deal deal = dealRepository.findById(id.intValue()).orElseThrow(()->new EntityNotFoundException("Deal with id " + id + " not found"));
        dealRepository.delete(deal);
    }
}
