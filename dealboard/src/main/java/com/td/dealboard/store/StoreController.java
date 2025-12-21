package com.td.dealboard.store;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import com.td.dealboard.deal.Deal;
import com.td.dealboard.deal.DealRepository;

@RestController
@RequestMapping("/api/stores")
public class StoreController {

    @Autowired
    private DealRepository dealRepository;

    @GetMapping
    public List<StoreWithDealCountDto> getAllStores() {
        // Group by store and count deals
        Map<String, Long> storeCounts = dealRepository.findAll()
                .stream()
                .filter(deal -> deal.getStore() != null)
                .collect(Collectors.groupingBy(
                        Deal::getStore,
                        Collectors.counting()
                ));

        return storeCounts.entrySet()
                .stream()
                .map(entry -> new StoreWithDealCountDto(entry.getKey(), entry.getValue()))
                .sorted((a, b) -> Long.compare(b.getDealCount(), a.getDealCount()))
                .collect(Collectors.toList());
    }
}