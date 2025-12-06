package com.td.dealboard.deal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;

@RestController("/api/deals")
public class DealController {
    @GetMapping("/mine")
    public ResponseEntity<List<Deal>> getMyDeals() {
        List<Deal> deals =  List.of(
                Deal.builder()
                        .name("Deal 1")
                        .description("Description 1")
                        .store("Store 1")
                        .price(9.99)
                        .build(),
                Deal.builder()
                        .name("Deal 2")
                        .description("Description 2")
                        .store("Store 2")
                        .price(19.99)
                        .build()
        );

        return ResponseEntity.ok(deals);
    }
}
