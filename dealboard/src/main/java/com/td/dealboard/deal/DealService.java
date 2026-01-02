package com.td.dealboard.deal;

import com.td.dealboard.user.User;
import com.td.dealboard.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class DealService {
    private final DealRepository dealRepository;
    private final UserRepository userRepository;
    private final Map<String, String> categoriesMap;

    public Page<DealDto> getDealsByUserStoresAndDeals(Integer userId, Pageable pageable) {
        User user = userRepository.findById(userId).orElseThrow();

        if (user.getSelectedStores().isEmpty()) {
            return Page.empty();
        }

        System.out.println(user.getSelectedStores() + " " + user.getTrackedProducts());
        Specification<Deal> spec =
                DealSpecifications.hasStoresAndKeywords(user.getSelectedStores(), user.getTrackedProducts());

        Page<Deal> result = dealRepository.findAll(spec, pageable);

        return result.map(deal -> toDto(deal, user));
    }

    private DealDto toDto(Deal deal) {
        return toDto(deal, null);
    }
    private DealDto toDto(Deal deal, User user) {
        boolean hasNotification = false;
        if (user != null) {
            // Sprawdź czy user ma aktywne powiadomienie dla tego deala
            hasNotification = user.getNotifications().containsKey(deal.getName());
        }
        return new DealDto(
                deal.getId(),
                deal.getName(),
                deal.getStore(),
                deal.getCategory(),
                deal.getCategoryCode(),
                deal.getPriceValue(),
                deal.getPriceAlt(),
                deal.getUnit(),
                deal.getDiscountPercentage(),
                deal.getPromoNotes(),
                hasNotification
        );
    }

    public void saveAllFromDto(List<DealDto> dtos, String store, LocalDate validSince, LocalDate validUntil) {
        List<Deal> entities = dtos.stream()
                .map(dto -> Deal.builder()
                        .name(dto.name())
                        .store(store)
                        .category(categoriesMap.getOrDefault(dto.category_code(), ""))
                        .categoryCode(dto.category_code())
                        .priceValue(dto.price_value())
                        .priceAlt(dto.price_alt())
                        .unit(dto.unit())
                        .discountPercentage(dto.discount_percent())
                        .promoNotes(dto.promo_notes())
                        .validSince(validSince)
                        .validUntil(validUntil)
                        .build()
                )
                .toList();

        dealRepository.saveAll(entities);
    }

    public Page<DealDto> getAllDealsWithFilters(String name, String store, String category, Double minPrice, Double maxPrice, Pageable pageable) {
        Specification<Deal> spec = Specification.allOf(
                 DealSpecifications.nameContains(name)
                ,DealSpecifications.hasStore(store)
                ,DealSpecifications.hasCategory(category)
                ,DealSpecifications.minPrice(minPrice)
                ,DealSpecifications.maxPrice(maxPrice));

        Pageable safePageable = sanitize(pageable);

        Page<Deal> result = dealRepository.findAll(spec, safePageable);
        return result.map(this::toDto);
    }

    private static final Set<String> ALLOWED_SORT_FIELDS = Set.of(
            "priceValue",
            "discountPercentage",
            "store",
            "name"
    );

    private Pageable sanitize(Pageable pageable) {
        Sort sort = pageable.getSort().stream()
                .filter(order -> ALLOWED_SORT_FIELDS.contains(order.getProperty()))
//                .map(order -> order.isAscending() ?
//                        Sort.Order.asc(order.getProperty()).nullsLast() :
//                        Sort.Order.desc(order.getProperty()).nullsLast()) //TODO: MAKE IT WORK
                .collect(Collectors.collectingAndThen(
                        Collectors.toList(),
                        Sort::by
                ));

        return PageRequest.of(
                pageable.getPageNumber(),
                pageable.getPageSize(),
                sort
        );
    }
}
