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
                        .categoryCode(dto.category_code())
                        .description(dto.description())
                        .priceValue(dto.price_value())
                        .priceAlt(dto.price_alt())
                        .unit(dto.unit())
                        .discountPercentage(dto.discount_percent())
                        .promoNotes(dto.promo_notes())
                        .build()
                )
                .toList();

        dealRepository.saveAll(entities);
    }
}
