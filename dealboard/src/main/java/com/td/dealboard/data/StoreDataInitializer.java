package com.td.dealboard.data;

import com.td.dealboard.scrapper.PromotionService;
import com.td.dealboard.store.Store;
import com.td.dealboard.store.StoreDto;
import com.td.dealboard.store.StoreRepository;
import com.td.dealboard.user.Role;
import com.td.dealboard.user.User;
import com.td.dealboard.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class StoreDataInitializer {
    private final StoreRepository storeRepository;
    private final PromotionService promotionService;

    @Bean
    public CommandLineRunner initStores() {
        return args -> {
            if (storeRepository.count()>0) {
                return;
            }
            List<StoreDto> stores = new ArrayList<>();
            try {
                stores = promotionService.getCurrentOfferShopLinks();
            } catch (Exception e) {
                log.error("Failed to load stores from promotion service", e);
            } finally {
                if (!stores.isEmpty()) {
                    List<Store> entities = stores.stream()
                            .map(StoreDto::toEntity)
                            .toList();
                    storeRepository.saveAll(entities);
                }
            }
        };
    }
}