package com.td.dealboard.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.text.Normalizer;
import java.util.*;

public class Utils {
    public static boolean isCorrectJsonArray(String json) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            JsonNode node = mapper.readTree(json);
            return node.isArray();
        } catch (JsonProcessingException e) {
            return false;
        }
    }


    //-------------------------------PROMOTION API------------------------------
    private static final OkHttpClient client = new OkHttpClient();

    public static List<String> getLeafletsURL(String baseUrl) {
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing or invalid parameter URL");
        }

        List<String> result = new ArrayList<>();
        Set<String> uniqueImages = new HashSet<>();
        int iterator = 1;

        while (true) {
            String presentURL = baseUrl + "?pageNumber=" + iterator;
            Request request = new Request.Builder().url(presentURL).build();

            try (Response response = client.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    break;
                }

                String html = response.body().string();
                Document doc = Jsoup.parse(html);

                Elements imgElements = doc.select("img.page-img");
                System.out.println("Strona " + iterator + ": znaleziono " + imgElements.size() + " obrazków");

                int addedCount = 0;

                for (Element img : imgElements) {
                    String src = removeBucketParam(img.attr("data-src"));
                    if (src == null || src.isBlank()) {
                        src = removeBucketParam(img.attr("src"));
                    }
                    if (src != null && !src.isBlank() && uniqueImages.add(src)) {
                        result.add(src);
                        addedCount++;
                        System.out.println("Dodano: " + src);
                    }
                }

                // Jeśli na tej stronie nie dodano nic nowego – przerwij pętlę
                if (addedCount == 0) {
                    System.out.println("Brak nowych obrazków na stronie " + iterator + ", kończę.");
                    break;
                }

            } catch (IOException e) {
                throw new RuntimeException("Failed to fetch leaflet page: " + presentURL, e);
            }

            iterator++;
        }

        return result;
    }
    public static String removeBucketParam(String url) {
        if (url == null || !url.contains("&bucket=")) {
            return url;
        }

        int index = url.lastIndexOf("&bucket=");
        if (index == -1 || index + 8 >= url.length()) {
            return url;
        }

        return url.substring(0, index);
    }

    public static String normalizeStore(String storeName) {
        // Zamiana polskich znaków na podstawowe (ą -> a itd.)
        String normalized = Normalizer.normalize(storeName, Normalizer.Form.NFD)
                .replaceAll("\\p{InCombiningDiacriticalMarks}+", "");

        // Zamiana spacji i znaków innych niż litery i cyfry na myślnik
        normalized = normalized.toLowerCase().replaceAll("[^a-z0-9]+", "-");

        // Usuwanie ewentualnych myślników na początku i końcu
        normalized = normalized.replaceAll("^-|-$", "");

        return normalized;
    }
}
