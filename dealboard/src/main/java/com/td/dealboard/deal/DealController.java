package com.td.dealboard.deal;

import com.td.dealboard.deal.dto.GroupedDealDto;
import com.td.dealboard.deal.dto.StoreRecommendationDto;
import com.td.dealboard.deal.dto.request.DealFilterRequest;
import com.td.dealboard.user.User;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
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
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        Pageable pageable = PageRequest.of(page, size);
        return dealService.getDealsFeed(userDetails.getUsername(), pageable);
    }

    @GetMapping("/all")
    public Page<DealDto> getDeals(
            @ParameterObject DealFilterRequest req,
            @ParameterObject
            @PageableDefault(size = 20, sort = "name", direction = Sort.Direction.ASC)
            Pageable pageable,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        String email = userDetails != null ? userDetails.getUsername() : null;
        return dealService.getAllDealsWithFilters(
                email,
                req,
                pageable
        );
    }


    @GetMapping("/products-suggestions")
    public ResponseEntity<List<String>> getProductSuggestions() {
        return ResponseEntity.ok(ProductSuggestions.POPULAR_PRODUCTS);
    }

    @GetMapping("/recommended-store")
    public ResponseEntity<StoreRecommendationDto> getRecommendedStore(
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        StoreRecommendationDto recommendation = dealService.getRecommendedStore(userDetails.getUsername());
        return ResponseEntity.ok(recommendation);
    }
}
