package com.td.dealboard.deal;

import com.td.dealboard.user.User;
import com.td.dealboard.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class DealService {

    @Autowired
    private DealRepository dealRepository;

    @Autowired
    private UserRepository userRepository;

    public Page<DealDto> getDealsByUserStoresAndDeals(Integer userId, Pageable pageable) {
        User user = userRepository.findById(userId).orElseThrow();

        if (user.getSelectedStores().isEmpty()) {
            return Page.empty();
        }

        System.out.println(user.getSelectedStores() + " " + user.getTrackedProducts());
        Specification<Deal> spec =
                DealSpecifications.hasStoresAndKeywords(user.getSelectedStores(), user.getTrackedProducts());

        Page<Deal> result = dealRepository.findAll(spec, pageable);


        return result.map(this::toDto);
    }

    private DealDto toDto(Deal deal) {
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
                deal.getPromoNotes()
        );
    }

    public void saveAllFromDto(List<DealDto> dtos, String store) {
        List<Deal> entities = dtos.stream()
                .map(dto -> Deal.builder()
                        .name(dto.name())
                        .store(store)
                        .category(dto.category())
                        .categoryCode(dto.category_code())
                        .priceValue(dto.price_value())
                        .priceAlt(dto.price_alt())
                        .unit(dto.unit())
                        .discountPercentage(dto.discount_percent())
                        .promoNotes(dto.promo_notes())
                        .build()
                )
                .toList();

        dealRepository.saveAll(entities);
    }

    public Page<Deal> getAllDealsWithFilters(String name, String store, String category, Double minPrice, Double maxPrice, Pageable pageable) {
        Specification<Deal> spec = Specification.allOf(
                 DealSpecifications.nameContains(name)
                ,DealSpecifications.hasStore(store)
                ,DealSpecifications.hasCategory(category)
                ,DealSpecifications.minPrice(minPrice)
                ,DealSpecifications.maxPrice(maxPrice));

        Pageable safePageable = sanitize(pageable);
        return dealRepository.findAll(spec, safePageable);
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
