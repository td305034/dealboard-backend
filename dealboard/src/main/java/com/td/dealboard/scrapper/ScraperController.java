package com.td.dealboard.scrapper;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.task.TaskExecutor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.util.*;
import java.util.concurrent.*;

@RestController
@RequestMapping("/api/scrapper")
@RequiredArgsConstructor
public class ScraperController {

        private static final Logger log = LoggerFactory.getLogger(ScraperController.class);

        private final TaskExecutor scrapperExecutor; // bean "scrapperExecutor"
        private final JpgToJsonService scrapperService;

//        @GetMapping("/run-prompt")
//        public ResponseEntity<?> runPrompt() {
//                File dir = new File("data/jpg");
//                File[] files = dir.listFiles((d, name) -> name.endsWith(".jpg"));
//
//                if (files == null || files.length == 0) {
//                        return ResponseEntity.ok("Directory is empty or does not exist.");
//                }
//
//                // Executor -> przekazujemy TaskExecutor jako Executor
//                Executor executor = runnable -> scrapperExecutor.execute(runnable);
//
//                long startTime = System.nanoTime();
//                List<PdfResult> results = scrapperService.processFilesParallel(leaflets, executor, 60);
//                long elapsedTime = System.nanoTime() - startTime;
//
//                System.out.println(elapsedTime);
//
//                // zwróć podsumowanie
//                long ok = results.stream().filter(r -> r.ok).count();
//                return ResponseEntity.ok(Map.of("total", results.size(), "ok", ok, "results", results));
//        }
}
