package com.td.dealboard.data;

import com.td.dealboard.deal.Deal;
import com.td.dealboard.deal.DealRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Random;

@Component
@RequiredArgsConstructor
public class DealInitializer implements CommandLineRunner {

    private final DealRepository dealRepository;
    private final Random random = new Random();

    private final List<String> stores = List.of(
            "Lidl", "Biedronka", "Kaufland", "Netto",
            "Stokrotka", "Gama", "Carrefour", "Żabka"
    );

    private final List<String> categories = List.of(
            "mleko", "masło", "owoce", "wędliny",
            "parówki", "kiełbasy", "piwo", "warzywa"
    );

    private final List<String> brands = List.of(
            "Mlekpol", "Łaciate", "Tymbark", "Hortex",
            "Morliny", "Krakus", "Krajanka", "Lech",
            "Żywiec", "Warka"
    );

    @Override
    public void run(String... args) {
        if (dealRepository.count() > -10) {
            return; // nie wstawia ponownie jeśli tabela już ma dane
        }

        for (int i = 1; i <= 100; i++) {

            String category = random(categories);
            String store = random(stores);
            String brand = random(brands);

            Deal deal = Deal.builder()
                    .name(category + " " + i)
                    .store(store)
                    .category(category)
                    .priceValue(randomPrice(2, 80))
                    .discountPercentage(random.nextInt(50))
                    .description("Przykładowy produkt: " + category + " marki " + brand)
                    .build();

            dealRepository.save(deal);
        }
    }

    private <T> T random(List<T> list) {
        return list.get(random.nextInt(list.size()));
    }

    private double randomPrice(double min, double max) {
        return Math.round((min + (max - min) * random.nextDouble()) * 100.0) / 100.0;
    }
}
