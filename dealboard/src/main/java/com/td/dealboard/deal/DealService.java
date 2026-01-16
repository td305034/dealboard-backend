package com.td.dealboard.deal;

import com.td.dealboard.store.Store;
import com.td.dealboard.user.User;
import com.td.dealboard.user.UserRepository;
import com.td.dealboard.store.StoreRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

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
    private final StoreRepository storeRepository;
    private final Map<String, String> categoriesMap;

    public Page<GroupedDealDto> getDealsFeed(
            Integer userId,
            Pageable pageable
    ) {
        User user = userRepository.findById(userId).orElseThrow();

        if (user.getSelectedStores().isEmpty() || user.getSelectedProducts().isEmpty()) {
            return Page.empty(pageable);
        }

        List<Store> stores = storeRepository.findAllByNameIn(
                user.getSelectedStores()
        );

        if (stores.isEmpty()) {
            return Page.empty(pageable);
        }

        Specification<Deal> spec =
                DealSpecifications.hasStores(stores);

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
        boolean hasNotification = true;
        System.out.println("Powiadomienia usera: " + user.getNotifications());
        System.out.println("Nazwa deala: " + deal.getName());
        System.out.println("Czy zawiera: " + user.getNotifications().containsKey(deal.getName()));
        if (user != null) {
            hasNotification = user.getNotifications().containsKey(deal.getName());
        }
        return new DealDto(
                deal.getId(),
                deal.getName(),
                deal.getStore().getName(),
                deal.getCategory(),
                deal.getCategoryCode(),
                deal.getPriceValue(),
                deal.getPriceAlt(),
                deal.getUnit(),
                deal.getDiscountPercentage(),
                deal.getPromoNotes(),
                deal.getValidUntil(),
                hasNotification,
                deal.getAppRequired()
        );
    }

    public void saveAllFromDto(List<DealDto> dtos, Store store, LocalDate validSince, LocalDate validUntil) {
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
                        .appRequired(dto.app_required())
                        .build()
                )
                .toList();

        dealRepository.saveAll(entities);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void saveFromDto(DealDto dto, Store store, LocalDate validSince, LocalDate validUntil) {
        Deal entity = Deal.builder()
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
                        .build();

        dealRepository.save(entity);
    }

    public Page<DealDto> getAllDealsWithFilters(String name, String storeName, String category, Double minPrice, Double maxPrice, Pageable pageable) {
        Store store = storeRepository.findByName(storeName).orElse(null);
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

        if (user.getSelectedStores().isEmpty() || user.getSelectedProducts().isEmpty()) {
            return null;
        }

        List<Store> stores = storeRepository.findAllByNameIn(user.getSelectedStores());
        if (stores.isEmpty()) {
            return null;
        }

        Specification<Deal> spec = DealSpecifications.hasStores(stores);
        List<Deal> deals = dealRepository.findAll(spec);

        Map<Store, Long> storeCounts = new HashMap<>();

        for (String keyword : user.getSelectedProducts()) {
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
                    .toList();

            if (matched.isEmpty()) {
                continue;
            }

            for (Deal deal : matched) {
                storeCounts.merge(deal.getStore(), 1L, Long::sum);
            }
        }

        if (storeCounts.isEmpty()) {
            return null;
        }

        Map.Entry<Store, Long> topStore = storeCounts.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .orElseThrow();

        return new StoreRecommendationDto(
                topStore.getKey().getName(),
                topStore.getValue().intValue()
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
