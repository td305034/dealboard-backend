package com.td.dealboard.data;

import com.td.dealboard.scrapper.PromotionService;
import com.td.dealboard.store.Store;
import com.td.dealboard.store.StoreDto;
import com.td.dealboard.store.StoreRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class StoreDataInitializer implements CommandLineRunner {

    private final StoreRepository storeRepository;
    private final PromotionService promotionService;

    @Override
    public void run(String... args) throws Exception {
        List<StoreDto> storeDtos = promotionService.getCurrentOfferShopLinks();
        if (storeDtos == null || storeDtos.isEmpty()) {
            return;
        }

        List<Store> stores = storeDtos.stream()
                .map(dto -> Store.builder()
                        .name(dto.getShopName())
                        .url(dto.getUrl())
                        .build())
                .collect(Collectors.toList());

        storeRepository.saveAll(stores);
    }
}

