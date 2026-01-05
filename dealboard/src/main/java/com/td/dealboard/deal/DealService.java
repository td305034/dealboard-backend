package com.td.dealboard.deal;

import com.td.dealboard.user.User;
import com.td.dealboard.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class DealService {
    private final DealRepository dealRepository;
    private final UserRepository userRepository;
    private final Map<String, String> categoriesMap;

    public Page<GroupedDealDto> getDealsFeed(
            Integer userId,
            Pageable pageable
    ) {
        User user = userRepository.findById(userId).orElseThrow();

        if (user.getSelectedStores().isEmpty() || user.getSelectedProducts().isEmpty()) {
            return Page.empty(pageable);
        }

        Specification<Deal> spec =
                DealSpecifications.hasStores(user.getSelectedStores());

        List<Deal> deals = dealRepository.findAll(spec);

        List<String> keywords = user.getSelectedProducts().stream()
                .sorted()
                .toList();

        List<GroupedDealDto> feed = new ArrayList<>();

        for (String keyword : keywords) {
            String lowered = keyword.toLowerCase();

            Pattern pattern = Pattern.compile(
                    "\\b" + Pattern.quote(lowered) + "\\b",
                    Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE
            );

            List<Deal> matched = deals.stream()
                    .filter(d ->
                            d.getName() != null &&
                                    pattern.matcher(d.getName()).find()
                    )
                    .sorted(Comparator.comparing(
                            Deal::getPriceValue,
                            Comparator.nullsLast(Double::compareTo)
                    ))
                    .toList();


            if (matched.isEmpty()) {
                continue;
            }

            Double cheapestPrice = matched.stream()
                    .map(Deal::getPriceValue)
                    .filter(Objects::nonNull)
                    .min(Double::compareTo)
                    .orElse(null);

            boolean first = true;
            for (Deal deal : matched) {
                boolean isCheapest =
                        cheapestPrice != null &&
                                deal.getPriceValue() != null &&
                                deal.getPriceValue().compareTo(cheapestPrice) == 0;

                feed.add(new GroupedDealDto(
                        keyword,
                        toDto(deal, user),
                        first,
                        isCheapest
                ));
                first = false;
            }
        }

        return toPage(feed, pageable);
    }


    public static <T> Page<T> toPage(List<T> list, Pageable pageable) {
        int start = (int) pageable.getOffset();

        if (start >= list.size()) {
            return Page.empty(pageable);
        }

        int end = Math.min(start + pageable.getPageSize(), list.size());

        return new PageImpl<>(
                list.subList(start, end),
                pageable,
                list.size()
        );
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
                deal.getValidUntil(),
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

    public StoreRecommendationDto getRecommendedStore(Integer userId) {
        User user = userRepository.findById(userId).orElseThrow();

        if (user.getSelectedStores().isEmpty()) {
            return null;
        }

        Specification<Deal> spec = DealSpecifications.hasStoresAndKeywords(
                user.getSelectedStores(),
                user.getSelectedProducts()
        );

        List<Deal> allDeals = dealRepository.findAll(spec);

        Map<String, Long> storeCounts = allDeals.stream()
                .collect(Collectors.groupingBy(Deal::getStore, Collectors.counting()));

        Optional<Map.Entry<String, Long>> topStore = storeCounts.entrySet().stream()
                .max(Map.Entry.comparingByValue());

        if (topStore.isEmpty()) {
            return null;
        }

        System.out.println("Liczba dealów dla netto: " + storeCounts.get("Netto"));
        return new StoreRecommendationDto(
                topStore.get().getKey(),
                topStore.get().getValue().intValue()
        );
    }

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
