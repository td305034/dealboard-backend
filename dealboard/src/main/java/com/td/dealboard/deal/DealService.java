package com.td.dealboard.deal;

import com.td.dealboard.user.User;
import com.td.dealboard.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class DealService {

    @Autowired
    private DealRepository dealRepository;

    @Autowired
    private UserRepository userRepository;

    public Page<DealDto> getDealsByUserStoresAndDeals(Integer userId, Pageable pageable) {
        User user = userRepository.findById(userId).orElseThrow();

        if (user.getSelectedStores().isEmpty()) {
            return Page.empty();
        }

        System.out.println(user.getSelectedStores() + " " + user.getTrackedProducts());
        Specification<Deal> spec =
                DealSpecification.hasStoresAndKeywords(user.getSelectedStores(), user.getTrackedProducts());

        Page<Deal> result = dealRepository.findAll(spec, pageable);


        return result.map(this::toDto);
    }

    private DealDto toDto(Deal deal) {
        return new DealDto(
                deal.getName(),
                deal.getStore(),
                deal.getCategory(),
                deal.getCategoryCode(),
                deal.getPriceValue(),
                deal.getPriceAlt(),
                deal.getUnit(),
                deal.getDiscountPercentage(),
                deal.getPromoNotes()
        );
    }

    public void saveAllFromDto(List<DealDto> dtos, String store) {
        List<Deal> entities = dtos.stream()
                .map(dto -> Deal.builder()
                        .name(dto.name())
                        .store(store)
                        .category(dto.category())
                        .categoryCode(dto.category_code())
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
