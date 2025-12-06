package com.td.dealboard.scrapper;

import com.td.dealboard.deal.DealDto;
import com.td.dealboard.deal.DealService;
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


@Service
@RequiredArgsConstructor
public class ScraperService {

    private static final Duration WAIT = Duration.ofSeconds(10);

    private static final String BASE_LIDL_URL = "https://www.lidl.pl";
    private static final String PROMOTION_BASE_URL = "https://www.lidl.pl/q/query/wyprzedaz";
    private static final String BASE_CARREFOUR_URL = "https://www.carrefour.pl/promocje/hity-cenowe?";

//    public Integer getLidlDeals(){
//        WebDriver driver = new ChromeDriver();
//
//        try {
//            driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(5));
//            WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
//            JavascriptExecutor js = (JavascriptExecutor) driver;
//
//            // 1) Wejdź raz bez offsetu żeby ustawić cookies/region i odczytać totalCount
//            driver.get(BASE_URL);
//            Thread.sleep(1000); // daj chwilę na ewentualne skrypty geolokalizacji
//            WebElement resultsInfo = wait.until(d -> d.findElement(By.cssSelector(".s-products-count-sort__count")));
//            int totalCount = Integer.parseInt(resultsInfo.getText().replaceAll("\\D+", ""));
//            System.out.println("Detected totalCount = " + totalCount);
//
//            driver.get(BASE_URL+"?offset=" + totalCount);
//            // 2) Wylicz liczbę checkpointów zgodnie ze wzorem
//            int numberOfCheckpoints = totalCount / 47 + 1;
//            System.out.println("numberOfCheckpoints = " + numberOfCheckpoints);
//
//            // 3) Zbiór do deduplikacji (LinkedHashSet zachowa kolejność dodawania)
//            Set<String> seenIds = new LinkedHashSet<>();
//
//            // 4) Iteruj checkpoints — w każdym zatrzymaj się i pobierz widoczne produkty
//            for (int checkpoint = 0; checkpoint < numberOfCheckpoints; checkpoint++) {
//                // Dynamiczne wyliczenie docelowej pozycji scrolla:
//                // Używamy aktualnej wysokości dokumentu, bo rośnie podczas ładowania.
//                long docHeight = ((Number) js.executeScript("return document.body.scrollHeight")).longValue();
//
//                // Oblicz docelową pozycję jako proporcję wysokości dokumentu.
//                // Dla checkpoint == 0 -> 0 (góra), dla ostatniego -> docHeight (dół)
//                double fraction = numberOfCheckpoints == 1 ? 0.0 : ((double) checkpoint / (numberOfCheckpoints - 1));
//                long target = (long) (docHeight * fraction);
//
//                // Stopniowe, wolne przewijanie od aktualnej pozycji do targetu (po kawałku),
//                // żeby nie pominąć lazy-loadowanych treści.
//                long currentPos = ((Number) js.executeScript("return window.pageYOffset || document.documentElement.scrollTop")).longValue();
//                if (currentPos > target) {
//                    // jeśli jesteśmy dalej niż target (np. poprzedni checkpoint przesunął nas dalej),
//                    // przewiń ostrzej w górę, ale raczej zaczynamy od góry wcześniej.
//                    js.executeScript("window.scrollTo(0, arguments[0]);", target);
//                    Thread.sleep(300);
//                } else {
//                    while (currentPos < target) {
//                        long step = 400; // przewijanie co 400px
//                        currentPos += step;
//                        if (currentPos > target) currentPos = target;
//                        js.executeScript("window.scrollTo(0, arguments[0]);", currentPos);
//                        Thread.sleep(450); // krótkie czekanie po każdym kroku
//                    }
//                }
//
//                // Po osiągnięciu targetu daj czas na dociągnięcie elementów
//                Thread.sleep(800);
//
//                // Dodatkowe lekkie "dociskowe" przewinięcie do dołu, żeby wywołać ewentualne fetch'e
//                js.executeScript("window.scrollBy(0, 200);");
//                Thread.sleep(400);
//                js.executeScript("window.scrollBy(0, -150);");
//                Thread.sleep(400);
//
//                // Stabilizacja: czekaj aż liczba widocznych produktów przestanie rosnąć (max iteracji)
//                int stableCounter = 0;
//                int prevCount = -1;
//                for (int i = 0; i < 10 && stableCounter < 3; i++) {
//                    List<WebElement> productsNow = driver.findElements(By.cssSelector(".product-grid-box"));
//                    int now = productsNow.size();
//                    if (now == prevCount) stableCounter++; else stableCounter = 0;
//                    prevCount = now;
//                    Thread.sleep(300);
//                }
//
//                // Pobierz widoczne produkty i dodaj unikalnie do zbioru
//                List<WebElement> products = driver.findElements(By.cssSelector(".product-grid-box"));
//                System.out.println("Checkpoint " + (checkpoint + 1) + "/" + numberOfCheckpoints + " -> found visible: " + products.size());
//
//                for (WebElement p : products) {
//                    // Najpierw spróbuj unikalnego atrybutu, jeśli istnieje
//                    String id = "";
//                    try {
//                        id = p.getAttribute("data-product-id");
//                    } catch (Exception ignored) {}
//
//                    // fallback — spróbuj kombinacji title + brand (trimowane)
//                    if (id == null || id.isEmpty()) {
//                        String title = safeGetText(p, ".product-grid-box__title, .odsc-title__link");
//                        String brand = safeGetText(p, ".product-grid-box__brand");
//                        id = (title + "||" + brand).trim();
//                    }
//
//                    if (id == null || id.isEmpty()) continue; // nieidentyfikowalny -> pomiń
//
//                    // jeżeli nie widzieliśmy jeszcze tego id, dodajemy i wypisujemy dane
//                    if (!seenIds.contains(id)) {
//                        seenIds.add(id);
//
//                        String title = safeGetText(p, ".product-grid-box__title, .odsc-title__link");
//                        String brand = safeGetText(p, ".product-grid-box__brand");
//                        String basePrice = safeGetText(p, ".ods-price__stroke-price");
//                        String price = safeGetText(p, ".ods-price__value");
//
//                        System.out.println("ADD: " + id + " | " + title + " | " + brand + " | " + basePrice + " | " + price);
//                    }
//                }
//
//                // mała pauza między checkpointami żeby nie przeciążyć serwera
//                Thread.sleep(500);
//            }
//
//            System.out.println("TOTAL UNIQUE COLLECTED = " + seenIds.size());
//            return ResponseEntity.ok("Zebrano unikalnych produktów: " + seenIds.size());
//
//        } catch (InterruptedException ie) {
//            Thread.currentThread().interrupt();
//            return ResponseEntity.status(500).body("Interrupted");
//        } catch (Exception e) {
//            e.printStackTrace();
//            return ResponseEntity.status(500).body("Error: " + e.getMessage());
//        } finally {
//            try { driver.quit(); } catch (Exception ignored) {}
//        }
//    }
//    // helper: bezpieczne pobranie texta z selektora wewnątrz elementu
//    private static String safeGetText(WebElement parent, String cssSelector) {
//        try {
//            List<WebElement> els = parent.findElements(By.cssSelector(cssSelector));
//            if (els.isEmpty()) return "";
//            return els.get(0).getText().trim();
//        } catch (Exception e) {
//            return "";
//        }
//    }


    private static final Logger log = LoggerFactory.getLogger(ScraperService.class);

    private final DealService dealService;
    private final ObjectMapper objectMapper;
    private final Semaphore pythonSemaphore = new Semaphore(30);

    public PdfResult processSingleFile(File child) {
        String name = child.getName();
        String store = child.getName().length() >= 4 ? child.getName().substring(0, 4) : "UNK";

        String json;
        try {
            pythonSemaphore.acquire();
            System.out.println("Thread " + Thread.currentThread().getName());

            try {
                json = PythonRunner.runPython(child.getAbsolutePath());
            } finally {
                pythonSemaphore.release();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return PdfResult.failed(name, "interrupted while waiting for python semaphore");
        } catch (Exception e) {
            log.warn("PythonRunner failed for {}: {}", name, e.getMessage());
            return PdfResult.failed(name, "python error: " + e.getMessage());
        }

        if (json == null || json.isBlank()) {
            return PdfResult.failed(name, "empty output from python");
        }

        String trimmed = json.trim();
        if (!trimmed.startsWith("[")) {
            log.warn("Non-array JSON from {}: startsWith={} ...", name, trimmed.length() > 100 ? trimmed.substring(0, 100) : trimmed);
            saveRaw(child.getName(), json);
            return PdfResult.failed(name, "not an array JSON");
        }

        try {
            List<DealDto> deals = objectMapper.readValue(json, new TypeReference<List<DealDto>>() {});
            if (deals == null || deals.isEmpty()) {
                return PdfResult.failed(name, "no deals parsed");
            }

            // deleguj transakcję do DealService
            dealService.saveAllFromDto(deals, store);
            return PdfResult.ok(name, deals.size());
        } catch (Exception e) {
            log.warn("Deserialization failed for {}: {}", name, e.getMessage());
            saveRaw(child.getName(), json);
            return PdfResult.failed(name, "deserialization error: " + e.getMessage());
        }
    }

    public List<PdfResult> processFilesParallel(File[] files, Executor executor, long perFileTimeoutSeconds) {
        List<Future<PdfResult>> futures = new ArrayList<>();
        ExecutorService svc = (executor instanceof ExecutorService) ? (ExecutorService) executor : Executors.newCachedThreadPool();

        for (File f : files) {
            futures.add(svc.submit(() -> processSingleFile(f)));
        }

        List<PdfResult> results = new ArrayList<>();
        for (Future<PdfResult> fu : futures) {
            try {
                results.add(fu.get(perFileTimeoutSeconds, TimeUnit.SECONDS));
            } catch (TimeoutException te) {
                fu.cancel(true);
                results.add(PdfResult.failed("unknown", "timeout"));
            } catch (Exception e) {
                results.add(PdfResult.failed("unknown", "error: " + e.getMessage()));
            }
        }

        // jeżeli svc utworzony lokalnie, zamknij
        if (!(executor instanceof ExecutorService)) {
            svc.shutdown();
        }
        return results;
    }

    private void saveRaw(String baseName, String rawJson) {
        try {
            java.nio.file.Path rawDir = java.nio.file.Path.of("data", "raw");
            java.nio.file.Files.createDirectories(rawDir);
            String out = baseName + "_" + System.currentTimeMillis() + ".json";
            java.nio.file.Files.writeString(rawDir.resolve(out), rawJson);
        } catch (Exception e) {
            log.warn("Could not save raw JSON: {}", e.getMessage());
        }
    }


private static String safeText(WebElement el) {
    try {
        return el.getText().trim();
    } catch (Exception e) {
        return "";
    }
}
}
