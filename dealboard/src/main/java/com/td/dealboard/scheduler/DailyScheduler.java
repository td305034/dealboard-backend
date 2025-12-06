package com.td.dealboard.scheduler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class DailyScheduler {
    private static final Logger log = LoggerFactory.getLogger(DailyScheduler.class);

    @Scheduled(cron = "${my.scraper.cron}", zone = "${my.scraper.zone}")
    public void runDailyTask() {
        log.info("Uruchamiam zadanie cykliczne: {}", java.time.ZonedDateTime.now());

    }
}
