package com.td.dealboard.scrapper;

import com.td.dealboard.deal.DealDto;
import com.td.dealboard.deal.DealService;
import com.td.dealboard.leaflet.Leaflet;
import lombok.RequiredArgsConstructor;
import org.openqa.selenium.WebElement;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;

import java.io.File;
import java.util.ArrayList;
import java.util.concurrent.*;

import static com.td.dealboard.util.Utils.isCorrectJsonArray;


@Service
@RequiredArgsConstructor
public class JpgToJsonService {

    private static final Logger log = LoggerFactory.getLogger(JpgToJsonService.class);

    private final DealService dealService;
    private final ObjectMapper objectMapper;
    private final Semaphore pythonSemaphore = new Semaphore(8);

    public void processSingleLeaflet(Leaflet leaflet) {
        Long id = leaflet.getId();
        String name = id.toString();
        String store = leaflet.getStore();
        List<String> pages = leaflet.getPages();
        List<String> results = new ArrayList<>();

        String json;
        try {
            pythonSemaphore.acquire();
            System.out.println("Thread " + Thread.currentThread().getName());
            try {
                for(String page : pages) {
                    json = PythonRunner.runPython(page);
                    results.add(json);
                }
            } finally {
                pythonSemaphore.release();
            }
        } catch (Exception e) {
            log.warn("PythonRunner failed for {}: {}", name, e.getMessage());
            return;
        }

        for(String jsonPage : results) {
            jsonPage = jsonPage.replace("None", "null");
            if(!isCorrectJsonArray(jsonPage)) {
                log.warn("Incorrect JSON array format for {}: {}", name, jsonPage);
                continue;
            }
            try {
                List<DealDto> deals = objectMapper.readValue(jsonPage, new TypeReference<List<DealDto>>() {
                });
                dealService.saveAllFromDto(deals, store);
            }
            catch (Exception e) {
                log.warn("Deserialization failed for {}: {}", name, e.getMessage());
                log.warn("Incorrect JSON: {}", jsonPage);
            }
        }
    }

    public void processFilesParallel(
            List<Leaflet> leaflets,
            Executor executor,
            long perFileTimeoutSeconds
    ) {

        ExecutorService svc =
                (executor instanceof ExecutorService)
                        ? (ExecutorService) executor
                        : Executors.newCachedThreadPool();

        List<Future<?>> futures = new ArrayList<>();

        for (Leaflet leaflet : leaflets) {
            futures.add(svc.submit(() -> processSingleLeaflet(leaflet)));
        }

        for (Future<?> f : futures) {
            try {
                f.get(perFileTimeoutSeconds, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                f.cancel(true);
                log.warn("Leaflet processing timed out");
            } catch (Exception e) {
                log.warn("Leaflet processing failed: {}", e.getMessage());
            }
        }

        if (!(executor instanceof ExecutorService)) {
            svc.shutdown();
        }
    }
}
