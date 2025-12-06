package com.td.dealboard.deal;

import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class DealService {

    private final DealRepository dealRepository;

    public DealService(DealRepository dealRepository) {
        this.dealRepository = dealRepository;
    }

    public void saveAllFromDto(List<DealDto> dtos, String store) {
        List<Deal> entities = dtos.stream()
                .map(dto -> Deal.builder()
                        .name(dto.name())
                        .store(store)
                        .category(dto.category())
                        .description(dto.description())
                        .price(dto.price_value())
                        .discountPercentage(dto.discount_percent())
                        .imageUrl(null)
                        .build()
                )
                .toList();

        dealRepository.saveAll(entities);
    }
}
