package com.td.dealboard.deal;

import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.util.Set;

public class DealSpecification {

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
}
