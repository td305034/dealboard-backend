package com.td.dealboard.scheduler;

import com.td.dealboard.leaflet.Leaflet;
import com.td.dealboard.leaflet.LeafletRepository;
import com.td.dealboard.scrapper.JpgToJsonService;
import com.td.dealboard.scrapper.PdfResult;
import com.td.dealboard.scrapper.PdfScraperService;
import com.td.dealboard.store.Store;
import com.td.dealboard.store.StoreRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.concurrent.Executor;

import static com.td.dealboard.scrapper.PythonRunner.runForLeaflets;

@Component
@RequiredArgsConstructor
@RestController("/api/test")
public class TestController {
    private static final Logger log = LoggerFactory.getLogger(DailyScheduler.class);
    private final PdfScraperService pdfScraperService;
    private final StoreRepository storeRepository;
    private final LeafletRepository leafletRepository;
    private final TaskExecutor scrapperExecutor; // bean "scrapperExecutor"
    private final JpgToJsonService scrapperService;

    @GetMapping("/process-leaflets")
    public void processLeaflets() {
        try {
            System.out.println("DailyScheduler running...");

            List<Leaflet> leaflets = leafletRepository.findAll();

            Executor executor = runnable -> scrapperExecutor.execute(runnable);
            scrapperService.processFilesParallel(leaflets, executor, 60);
        } catch (Exception e) {
            log.error("Error in DailyScheduler: {}", e.getMessage(), e);
        }
    }

    @GetMapping("/get-leaflets")
    public void getLeaflets() {
        List<Store> stores = storeRepository.findAll();
        pdfScraperService.runForStores(stores);
    }
}
