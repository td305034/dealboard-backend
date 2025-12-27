package com.td.dealboard.deal;

import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.util.Set;

public class DealSpecifications {

    public static Specification<Deal> hasStoresAndKeywords(
            Set<String> stores,
            Set<String> keywords
    ) {
        return (root, query, cb) -> {

            Predicate storePredicate = root.get("store").in(stores);

            Predicate keywordPredicate = cb.or(
                    keywords.stream()
                            .map(k ->
                                    cb.like(
                                            cb.lower(root.get("name")),
                                            "%" + k.toLowerCase() + "%"
                                    )
                            )
                            .toArray(Predicate[]::new)
            );

            return cb.and(storePredicate, keywordPredicate);
        };
    }

    public static Specification<Deal> hasStore(String store) {
        return (root, query, cb) ->
                store == null ? null : cb.equal(root.get("store"), store);
    }

    public static Specification<Deal> hasCategory(String category) {
        return (root, query, cb) ->
                category == null ? null : cb.equal(root.get("category"), category);
    }

    public static Specification<Deal> minPrice(Double minPrice) {
        return (root, query, cb) ->
                minPrice == null ? null : cb.ge(root.get("priceValue"), minPrice);
    }

    public static Specification<Deal> maxPrice(Double maxPrice) {
        return (root, query, cb) ->
                maxPrice == null ? null : cb.le(root.get("priceValue"), maxPrice);
    }
}
