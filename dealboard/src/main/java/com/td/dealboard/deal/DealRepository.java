package com.td.dealboard.deal;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface DealRepository extends JpaRepository<Deal, Integer> {
    Page<Deal> findByStoreIn(List<String> stores, Pageable pageable);

    Page<Deal> findAll(Specification<Deal> spec, Pageable pageable);
    List<Deal> findAll(Specification<Deal> spec);
}
