package com.td.dealboard.scheduler;

import com.td.dealboard.leaflet.LeafletRepository;
import com.td.dealboard.scrapper.JpgToJsonService;
import com.td.dealboard.store.StoreRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.task.TaskExecutor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DailyScheduler {
    private static final Logger log = LoggerFactory.getLogger(DailyScheduler.class);
    private final PdfScraperService pdfScraperService;
    private final StoreRepository storeRepository;
    private final LeafletRepository leafletRepository;
    private final TaskExecutor scrapperExecutor; // bean "scrapperExecutor"
    private final JpgToJsonService scrapperService;


    //@Scheduled(cron = "${my.scraper.cron}", zone = "${my.scraper.zone}")
//    @Scheduled(fixedRate=20000)
//    public void runDailyTask() {
//        try {
//            System.out.println("DailyScheduler running...");
//            List<Store> stores = storeRepository.findAll();
//            pdfScraperService.runForStores(stores);
//            List<Leaflet> leaflets = leafletRepository.findAll();
//
//            Executor executor = runnable -> scrapperExecutor.execute(runnable);
//            scrapperService.processFilesParallel(leaflets, executor, 60);
//        } catch (Exception e) {
//            log.error("Error in DailyScheduler: {}", e.getMessage(), e);
//        }
//    }
}
