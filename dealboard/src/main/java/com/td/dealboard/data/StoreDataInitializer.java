package com.td.dealboard.data;

import com.td.dealboard.scrapper.PromotionService;
import com.td.dealboard.store.Store;
import com.td.dealboard.store.StoreDto;
import com.td.dealboard.store.StoreRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.*;
import java.util.stream.Collectors;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class StoreDataInitializer {
    private final StoreRepository storeRepository;
    private final PromotionService promotionService;

    @Bean
    public CommandLineRunner initStores() {
        return args -> {
            if (storeRepository.count() > 0) {
                return;
            }

            List<StoreDto> stores = new ArrayList<>();
            try {
                stores = promotionService.getCurrentOfferShopLinks();
            } catch (Exception e) {
                log.error("Failed to load stores from promotion service", e);
            }

            if (stores.isEmpty()) {
                return;
            }

            List<Store> entities = stores.stream()
                    .map(StoreDto::toEntity)
                    .filter(s -> s.getName() != null && s.getUrl() != null)
                    .collect(Collectors.toMap(
                            s -> s.getName() + "|" + s.getUrl(),
                            s -> s,
                            (existing, replacement) -> existing))
                    .values()
                    .stream()
                    .collect(Collectors.toList());

            if (entities.isEmpty()) {
                return;
            }

            // Load existing names and urls from DB to avoid duplicate key errors
            Set<String> existingNames = storeRepository.findAll().stream()
                    .map(Store::getName)
                    .filter(Objects::nonNull)
                    .map(StoreDataInitializer::normalize)
                    .collect(Collectors.toSet());

            Set<String> existingUrls = storeRepository.findAll().stream()
                    .map(Store::getUrl)
                    .filter(Objects::nonNull)
                    .map(StoreDataInitializer::normalize)
                    .collect(Collectors.toSet());

            List<Store> toSave = entities.stream()
                    .filter(s -> !existingNames.contains(s.getName()) && !existingUrls.contains(s.getUrl()))
                    .collect(Collectors.toList());

            if (toSave.isEmpty()) {
                log.info("No new stores to save after deduplication and existing DB check.");
                return;
            }

            try {
                storeRepository.saveAll(toSave);
                log.info("Saved {} new stores.", toSave.size());
            } catch (DataIntegrityViolationException dive) {
                log.warn("Bulk save failed due to DataIntegrityViolationException, falling back to per-item insert. Error: {}", dive.getMessage());
                // Try saving one-by-one to be able to skip duplicates and continue
                for (Store s : toSave) {
                    try {
                        if (storeRepository.existsByName(s.getName()) || storeRepository.existsByUrl(s.getUrl())) {
                            log.info("Skipping store (exists): {}", s.getName());
                            continue;
                        }
                        storeRepository.save(s);
                    } catch (DataIntegrityViolationException ex) {
                        log.warn("Failed to save store '{}' due to constraint violation, skipping. Error: {}", s.getName(), ex.getMessage());
                    } catch (Exception ex) {
                        log.error("Unexpected error while saving store '{}': {}", s.getName(), ex.getMessage(), ex);
                    }
                }
            }
        };
    }

    private static String normalize(String s) {
        if (s == null) return null;
        return s.trim().toLowerCase(Locale.ROOT);
    }
}