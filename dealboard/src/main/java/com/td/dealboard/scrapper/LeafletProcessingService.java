package com.td.dealboard.scrapper;

import com.google.common.util.concurrent.RateLimiter;
import com.td.dealboard.deal.DealDto;
import com.td.dealboard.deal.DealRepository;
import com.td.dealboard.deal.DealService;
import com.td.dealboard.leaflet.Leaflet;
import com.td.dealboard.leaflet.LeafletRepository;
import com.td.dealboard.store.Store;
import com.td.dealboard.store.StoreRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;

import java.util.ArrayList;
import java.util.concurrent.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.td.dealboard.util.Utils.isCorrectJsonArray;


@Service
@RequiredArgsConstructor
public class LeafletProcessingService {

    private static final Logger log = LoggerFactory.getLogger(LeafletProcessingService.class);
    private static final long PER_FILE_TIMEOUT_SECONDS = 60;
    private static final RateLimiter tokenLimiter = RateLimiter.create(4500);

    private final LeafletRepository leafletRepository;
    private final ThreadPoolTaskExecutor scrapperExecutor;
    private final StoreRepository storeRepository;
    private final DealRepository dealRepository;
    private final DealService dealService;
    private final ObjectMapper objectMapper;

    private final Semaphore pythonSemaphore = new Semaphore(8);

    public void processLeaflets() {
        List<Leaflet> leaflets = leafletRepository.findAll();
        processFilesParallel(leaflets);
    }

    private void processFilesParallel(List<Leaflet> leaflets) {
        List<Future<?>> futures = new ArrayList<>();

        for (Leaflet leaflet : leaflets) {
            if (leaflet.getValidUntil().isBefore(LocalDate.now())) {
                log.info("Skipping leaflet {} as it is not currently valid", leaflet.getId());
                continue;
            }
            else if(leaflet.getValidSince()!=null){
                if(leaflet.getValidSince().isAfter(LocalDate.now())) {
                    log.info("Skipping leaflet {} as it is not currently valid", leaflet.getId());
                    continue;
                }
            }
            futures.add(scrapperExecutor.submit(() -> processSingleLeaflet(leaflet)));
        }

        for (Future<?> f : futures) {
            try {
                f.get(PER_FILE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                f.cancel(true);
                log.warn("Leaflet processing timed out");
            } catch (Exception e) {
                log.warn("Leaflet processing failed: {}", e.getMessage());
            }
        }
    }

    private void processSingleLeaflet(Leaflet leaflet) {
        Long id = leaflet.getId();
        String name = id.toString();
        Store store = storeRepository.findByName(leaflet.getStoreName()).orElseThrow(() -> new RuntimeException("Store not found"));
        List<String> pages = leaflet.getPages();
        List<String> results = new ArrayList<>();

        LocalDate validSince = leaflet.getValidSince();
        LocalDate validUntil = leaflet.getValidUntil();

        String json;

        int batchSize = 5;
        int maksTokensPerBatch = 4120;
        for (int i = 0; i < pages.size(); i += batchSize) {
            int end = Math.min(i + batchSize, pages.size());
            List<String> batch = pages.subList(i, end);

            try {
                tokenLimiter.acquire((int) (maksTokensPerBatch*1.2));
                pythonSemaphore.acquire();
                try {
                    json = PythonRunner.runPython("ai_runner", batch);
                    results.add(json);
                } finally {
                    pythonSemaphore.release();
                }
            } catch (Exception e) {
                log.warn("PythonRunner failed for {} from store {}: {}", name, store, e.getMessage());
                return;
            }
        }

        for(String jsonPage : results) {
            jsonPage = jsonPage.replace("None", "null");
            if(!isCorrectJsonArray(jsonPage)) {
                log.warn("Incorrect JSON array format for {}: {}", name, jsonPage);
                continue;
            }
            try {
                Pattern letterPattern = Pattern.compile(".*[A-Za-zĄąĆćĘęŁłŃńÓóŚśŻżŹź].*");
                List<String> blacklistedUnits = List.of("zł", "pln", "zl", "zł.", "PLN", "lub", "za");

                List<DealDto> deals = objectMapper.readValue(jsonPage, new TypeReference<List<DealDto>>() {});

                List<DealDto> filteredDeals = deals.stream()
                        .map(deal -> deal.withDefaultUnitIfInvalid(blacklistedUnits))
                        .filter(deal -> deal.name() != null && letterPattern.matcher(deal.name()).matches())
                        .filter(deal ->
                                (deal.price_value() != null && deal.price_value() > 0)
                                        ||
                                        (deal.price_value() == null && deal.price_alt() != null
                                                && !deal.price_alt().isBlank()
                                                && !deal.price_alt().equalsIgnoreCase("supercena"))
                        )
                        .collect(Collectors.toList());

                List<DealDto> filteredDealsToSave = filteredDeals.stream()
                        .filter(deal -> !dealRepository.existsByNameAndStoreAndValidSinceAndValidUntil(
                                deal.name(), store, validSince, validUntil))
                        .collect(Collectors.toList());

                dealService.saveAllFromDto(filteredDealsToSave, store, validSince, validUntil);

                try {
                    dealService.saveAllFromDto(filteredDeals, store, validSince, validUntil);
                }
                catch (DataIntegrityViolationException e){
                    log.warn("Bulk save failed for {}: {}, falling back to per-item insert.", name, e.getMessage());
                    for (DealDto dto : filteredDeals) {
                        try {
                            dealService.saveFromDto(dto, store, validSince, validUntil);
                        }
                        catch (DataIntegrityViolationException err) {
                            log.warn("Duplicate deal skipped: {}", dto.name());
                        }
                    }
                }

            } catch (Exception e) {
                log.warn("Deserialization failed for {}: {}", name, e.getMessage());
                log.warn("JSON: {}", jsonPage);
            }
        }
    }

}
