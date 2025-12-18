package com.td.dealboard.scrapper;

import com.td.dealboard.deal.Deal;
import com.td.dealboard.leaflet.Leaflet;
import com.td.dealboard.leaflet.LeafletDto;
import com.td.dealboard.leaflet.LeafletRepository;
import com.td.dealboard.store.Store;
import lombok.RequiredArgsConstructor;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.ParameterizedTypeReference;
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
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;

@Service
@RequiredArgsConstructor
public class PdfScraperService {
    private static final Logger log = LoggerFactory.getLogger(PdfScraperService.class);
    private final HttpClient httpClient = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    private final LeafletRepository leafletRepo;

    private final PromotionService promotionService;

    // katalog bazowy zapisu
    private final Path baseDir = Paths.get("/data/pdf");

    public void runForStores(List<Store> stores) {
        int i = 0; //just for development, we dont need to get all shops' leaflets
        for (Store store : stores) {
            try {
                processStore(store);
            } catch (Exception e) {
                log.error("Error with processing {}: {}", store.getId(), e.getMessage(), e);
            }
            if(i++>1) break;
        }
    }

    private void processStore(Store store) throws IOException, InterruptedException {
        String name = store.getName();

        List<LeafletDto> dtos = promotionService.findPromotionalLeaflet(name);
        System.out.println(dtos.get(0));
        if (dtos == null || dtos.isEmpty()) {
            return;
        }

        List<Leaflet> entities = dtos.stream()
                .map(Leaflet::new)
                .collect(Collectors.toList());

        leafletRepo.saveAll(entities);
    }
}
