package com.td.dealboard.store;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface StoreRepository extends JpaRepository<Store, Integer> {
    Optional<Store> findByUrl(String url);
    Optional<Store> findByName(String url);
}