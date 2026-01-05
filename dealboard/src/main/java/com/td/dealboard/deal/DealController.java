package com.td.dealboard.deal;

import com.td.dealboard.user.User;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

@RestController
@RequestMapping("/api/deals")
public class DealController {

    @Autowired
    private DealService dealService;

    @GetMapping("/mine")
    public Page<GroupedDealDto> getMyDeals(
            @AuthenticationPrincipal User user,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        Pageable pageable = PageRequest.of(page, size);

        return dealService.getDealsFeed(user.getId(), pageable);
    }

    @GetMapping("/all")
    public Page<DealDto> getDeals(
            @RequestParam(required = false) String name,
            @RequestParam(required = false) String store,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) Double minPrice,
            @RequestParam(required = false) Double maxPrice,

            @ParameterObject
            @PageableDefault(
                    size = 20,
                    sort = "name",
                    direction = Sort.Direction.ASC
            )
            Pageable pageable
    ) {
        return dealService.getAllDealsWithFilters(
                name,
                store,
                category,
                minPrice,
                maxPrice,
                pageable);
    }

    @GetMapping("/products-suggestions")
    public List<String> getProductSuggestions() {
        return ProductSuggestions.POPULAR_PRODUCTS;
    }

    @GetMapping("/recommended-store")
    public StoreRecommendationDto getRecommendedStore(
            @AuthenticationPrincipal User user
    ) {
        return dealService.getRecommendedStore(user.getId());
    }
}
