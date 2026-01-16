package com.td.dealboard.leaflet;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;

public interface LeafletRepository extends JpaRepository<Leaflet, Integer> {
    boolean existsByUrl(String url);

    @Modifying
    @Transactional
    @Query("DELETE FROM Leaflet l WHERE l.validUntil < :today")
    void deleteExpired(@Param("today") LocalDate today);
}
