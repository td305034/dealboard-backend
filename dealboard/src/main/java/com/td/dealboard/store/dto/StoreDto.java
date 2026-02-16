package com.td.dealboard.store.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.td.dealboard.store.Store;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class StoreDto {
    private String shopName;
    private String url;

    public Store toEntity() {
        return Store.builder()
                .name(this.shopName)
                .url(this.url)
                .build();
    }
}