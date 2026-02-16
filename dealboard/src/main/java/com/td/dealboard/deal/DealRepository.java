package com.td.dealboard.deal;

import com.td.dealboard.store.Store;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;
import java.util.List;

public interface DealRepository extends JpaRepository<Deal, Integer> {
    Page<Deal> findAll(Specification<Deal> spec, Pageable pageable);
    List<Deal> findAll(Specification<Deal> spec);

    boolean existsByNameAndStoreAndValidSinceAndValidUntil(String name, Store store, LocalDate validSince, LocalDate validUntil);

}
