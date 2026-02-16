package com.td.dealboard.deal;

import java.time.LocalDate;
import java.util.List;

public record DealDto(
        Long id,
        String name,
        String store,
        String category,
        String category_code,
        Double price_value,
        String price_alt,
        String unit,
        Integer discount_percent,
        String promo_notes,
        LocalDate valid_until,
        Boolean has_notification,
        Boolean app_required
) {
    public DealDto withDefaultUnitIfInvalid(List<String> blacklisted) {
        if (unit == null || blacklisted.stream().anyMatch(b -> unit.toLowerCase().contains(b))) {
            return new DealDto(id, name, store, category, category_code, price_value, price_alt, "szt", discount_percent, promo_notes, valid_until, has_notification, app_required);
        }
        return this;
    }
}
