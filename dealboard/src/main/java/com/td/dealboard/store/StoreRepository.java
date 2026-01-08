package com.td.dealboard.store;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface StoreRepository extends JpaRepository<Store, Integer> {
    Optional<Store> findByUrl(String url);
    Optional<Store> findByName(String name);
    List<Store> findAllByNameIn(Collection<String> names);

    Optional<Store> findFirstByName(String name);

    boolean existsByName(String name);
    boolean existsByUrl(String url);

}