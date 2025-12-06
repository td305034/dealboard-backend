package com.td.dealboard.data;

import com.td.dealboard.store.Store;
import com.td.dealboard.store.StoreRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.nio.file.Paths;

@Component
@RequiredArgsConstructor
public class StoreDataInitializer implements CommandLineRunner {

    private final StoreRepository storeRepository;

    @Override
    public void run(String... args) throws Exception {
        try(InputStream is = StoreDataInitializer.class.getResourceAsStream("/stores.csv");
            BufferedReader br = new BufferedReader(new InputStreamReader(is))) {
            br.lines()
                    .map(line -> line.split(","))
                    .forEach(cols -> {
                        String name = cols[0].trim();
                        String url = cols[1].trim();
                        storeRepository.findByName(name).or(() -> storeRepository.findByUrl(url)).ifPresentOrElse(
                                existing -> {
                                    existing.setName(name);
                                    existing.setUrl(url);
                                    storeRepository.save(existing);
                                },
                                () -> storeRepository.save(Store.builder().name(name).url(url).build())
                        );
                    });
        }
        catch(NullPointerException e){
            System.out.println("Error: " + e);
            System.out.println("Brak pliku stores.csv w zasobach.");
        }
    }
}

