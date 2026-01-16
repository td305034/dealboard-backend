package com.td.dealboard.scrapper;

import com.td.dealboard.leaflet.Leaflet;
import com.td.dealboard.leaflet.LeafletDto;
import com.td.dealboard.leaflet.LeafletRepository;
import com.td.dealboard.store.Store;
import com.td.dealboard.store.StoreDto;
import com.td.dealboard.store.StoreRepository;
import com.td.dealboard.util.Utils;
import lombok.RequiredArgsConstructor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class PromotionService {

    private static final Logger log = LoggerFactory.getLogger(PromotionService.class);

    private final LeafletRepository leafletRepository;
    private final StoreRepository storeRepository;

    private static final Pattern DATE_PATTERN =
            Pattern.compile("(\\d{2}\\.\\d{2})(?:\\s*[-–]\\s*(\\d{2}\\.\\d{2}))?");

    private final OkHttpClient client = new OkHttpClient();

    /**
     * Scheduler – codziennie o 09:00
     */
    @Scheduled(cron = "0 0 9 * * *")
    public void fetchLeafletsScheduler() {
        try {
            List<Store> stores = List.of(
                    storeRepository.findByName("Lidl").orElse(null),
                    storeRepository.findByName("Biedronka").orElse(null),
                    storeRepository.findByName("Kaufland").orElse(null),
                    storeRepository.findByName("Carrefour").orElse(null),
                    storeRepository.findByName("Netto").orElse(null)
            );

            List<LeafletDto> allLeaflets = new ArrayList<>();
            for (Store store : stores) {
                if (store != null) {
                    allLeaflets.addAll(fetchLeafletsForStore(store));
                }
            }

            processLeaflets(allLeaflets);

        } catch (Exception e) {
            log.error("Error in PromotionService scheduler: {}", e.getMessage(), e);
        }
    }

    /**
     * Procesowanie gazetki – zapis do bazy + usuwanie przeterminowanych
     */
    public void processLeaflets(List<LeafletDto> fetchedLeaflets) {
        LocalDate today = LocalDate.now();

        // usuń przeterminowane gazetki
        leafletRepository.deleteExpired(today);

        for (LeafletDto dto : fetchedLeaflets) {
            if (!leafletRepository.existsByUrl(dto.leafletLink())) {
                leafletRepository.save(new Leaflet(dto));
            }
        }
    }

    /**
     * Pobiera listę gazetek dla sklepu
     */
    public List<LeafletDto> fetchLeafletsForStore(Store store) {
        try {
            return findPromotionalLeaflet(store.getName());
        } catch (Exception e) {
            log.error("Error fetching leaflets for store {}: {}", store.getName(), e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    /**
     * Pobiera listę gazetek dla podanej nazwy sklepu
     */
    public List<LeafletDto> findPromotionalLeaflet(String storeName) throws IOException {
        if (storeName == null || storeName.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing or invalid storeName");
        }

        if (storeName.equalsIgnoreCase("Intermarché")) {
            storeName = "Intermarche";
        }

        String cleanedStore = Utils.normalizeStore(storeName);
        String baseUrl = "https://blix.pl/sklep/" + cleanedStore;

        Request request = new Request.Builder().url(baseUrl).build();
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) throw new IOException("HTTP error: " + response);

            String html = response.body().string();
            Document doc = Jsoup.parse(html);

            Elements leafletLinks = doc.select("a[href*='gazetka'], a[href*='leaflet']");
            if (leafletLinks.isEmpty()) return Collections.emptyList();

            List<LeafletDto> result = new ArrayList<>();
            for (Element a : leafletLinks) {
                String link = a.attr("href");
                String image = "";
                LocalDate validSince = null;
                LocalDate validUntil;

                Document leafletDoc = Jsoup.connect(link).get();
                Element h1 = leafletDoc.selectFirst("h1.leaflet-data__name");

                if (h1 != null) {
                    DateRange dates = parseDatesFromH1(h1.text());
                    validSince = dates.start();
                    validUntil = dates.end();
                } else {
                    validUntil = LocalDate.now();
                }

                if (validUntil.isBefore(LocalDate.now())) continue;

                Element img = a.selectFirst("img");
                if (img != null) image = img.attr("data-src");

                List<String> pages = Utils.getLeafletsURL(link);
                LocalDate downloadDate = LocalDate.now();

                if (link.toLowerCase().contains(cleanedStore.toLowerCase())) {
                    result.add(new LeafletDto(
                            storeName, link, image, validSince, validUntil, pages, downloadDate
                    ));
                }
            }
            return result;
        }
    }

    private record DateRange(LocalDate start, LocalDate end) {}

    private DateRange parseDatesFromH1(String text) {
        Matcher matcher = DATE_PATTERN.matcher(text);
        LocalDate startDate = null;
        LocalDate endDate = null;
        int year = LocalDate.now().getYear();

        List<String> datesFound = new ArrayList<>();
        while (matcher.find()) {
            datesFound.add(matcher.group(1));
            if (matcher.group(2) != null) {
                datesFound.add(matcher.group(2));
            }
        }

        if (datesFound.isEmpty()) {
            endDate = LocalDate.now();
            return new DateRange(null, endDate);
        }

        if (datesFound.size() == 1) {
            String singleDate = datesFound.get(0);
            if (text.toLowerCase().contains("od")) {
                startDate = parseDayMonth(singleDate, year);
            } else if (text.toLowerCase().contains("do")) {
                endDate = parseDayMonth(singleDate, year);
            } else {
                endDate = parseDayMonth(singleDate, year);
            }
        } else {
            startDate = parseDayMonth(datesFound.get(0), year);
            endDate = parseDayMonth(datesFound.get(1), year);
        }

        if (startDate != null) startDate = normalizeYear(startDate);

        if (endDate == null) {
            endDate = LocalDate.now();
        } else {
            endDate = normalizeYear(endDate);
        }

        return new DateRange(startDate, endDate);
    }


    private LocalDate parseDayMonth(String value, int year) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd.MM.yyyy");
        return LocalDate.parse(value + "." + year, formatter);
    }

    private LocalDate normalizeYear(LocalDate date) {
        LocalDate now = LocalDate.now();
        if (date.isAfter(now.plusMonths(10))) return date.minusYears(1);
        if (date.isBefore(now.minusMonths(10))) return date.plusYears(1);
        return date;
    }

    public List<StoreDto> getCurrentOfferShopLinks() throws IOException {
        String baseUrl = "https://blix.pl/sklepy";
        Request request = new Request.Builder().url(baseUrl).build();
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("HTTP error : " + response);
            }
            String html = response.body().string();
            Document doc = Jsoup.parse(html);

            Elements links = doc.select("div.section-n__items.section-n__items--brands > a");

            List<StoreDto> result = new ArrayList<>();
            for (Element a : links) {
                String title = a.attr("title");
                String href = a.attr("href");
                if (!href.startsWith("http")) {
                    href = "https://blix.pl" + href;
                }
                result.add(new StoreDto(title, href));
            }
            return result;
        }
    }
}

