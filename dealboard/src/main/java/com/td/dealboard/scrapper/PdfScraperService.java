package com.td.dealboard.scrapper;

import com.td.dealboard.store.Store;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.*;
import java.time.LocalDate;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class PdfScraperService {
    private static final Logger log = LoggerFactory.getLogger(PdfScraperService.class);
    private final HttpClient httpClient = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    // katalog bazowy zapisu
    private final Path baseDir = Paths.get("/data/pdf");

    public void runForStores(List<Store> stores) {
        for (Store store : stores) {
            try {
                processStore(store);
            } catch (Exception e) {
                log.error("Błąd przetwarzania sklepu {}: {}", store.getId(), e.getMessage(), e);
            }
        }
    }

    private void processStore(Store store) throws IOException, InterruptedException {
        log.info("Przetwarzam sklep {} -> {}", store.getId(), store.getUrl());
        Document doc = Jsoup.connect(store.getUrl())
                .userAgent("Mozilla/5.0 (compatible; PdfScraper/1.0)")
                .timeout(15_000)
                .get();

        Elements links = doc.select("a[href$=.pdf], a[href*=.pdf?]"); // linki kończące się na .pdf albo z parametrem
        if (links.isEmpty()) {
            log.info("Brak linków PDF znalezionych dla sklepu {}", store.getId());
            return;
        }

        //Path storeDir = baseDir.resolve(store.getName()).resolve(LocalDate.now().toString());
        Path storeDir = baseDir.resolve(store.getName());
        Files.createDirectories(storeDir);

        for (Element a : links) {
            String href = a.absUrl("href");
            if (href == null || href.isBlank()) continue;
            try {
                downloadPdfIfNew(href, storeDir);
            } catch (Exception e) {
                log.warn("Nie udało się pobrać {}: {}", href, e.getMessage());
            }
        }
    }

    private void downloadPdfIfNew(String pdfUrl, Path targetDir) throws IOException, InterruptedException {
        String fileName = extractFileNameFromUrl(pdfUrl);
        if (fileName == null || fileName.isBlank()) fileName = "gazetka.pdf";

        Path target = targetDir.resolve(fileName);

        // proste sprawdzenie duplikatu (możesz rozszerzyć o hash)
        if (Files.exists(target)) {
            log.info("Plik {} już istnieje — pomijam", target);
            return;
        }

        log.info("Pobieram {} -> {}", pdfUrl, target);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(pdfUrl))
                .GET()
                .header("User-Agent", "Mozilla/5.0 (compatible; PdfScraper/1.0)")
                .build();

        HttpResponse<InputStream> response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
        int status = response.statusCode();
        if (status >= 200 && status < 300) {
            try (InputStream is = response.body()) {
                Files.copy(is, target, StandardCopyOption.REPLACE_EXISTING);
            }
            log.info("Zapisano: {}", target);
        } else {
            throw new IOException("HTTP status: " + status);
        }
    }

    private String extractFileNameFromUrl(String url) {
        try {
            String path = URI.create(url).getPath();
            if (path == null) return null;
            int idx = path.lastIndexOf('/');
            if (idx >= 0 && idx + 1 < path.length()) return path.substring(idx + 1);
            return path;
        } catch (Exception e) {
            return null;
        }
    }
}
