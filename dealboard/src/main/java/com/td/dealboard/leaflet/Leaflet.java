package com.td.dealboard.leaflet;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDate;
import java.util.List;

@Entity
@Table(name = "leaflets")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Leaflet {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String store;

    @Column(unique = true)
    private String url;

    @Column(unique = true)
    private String imageUrl;

    private String validUntil;

    @ElementCollection
    @CollectionTable(name = "leaflet_pages", joinColumns = @JoinColumn(name = "leaflet_id"))
    @Column(name = "page_url")
    private List<String> pages;

    private LocalDate downloadDate;

    public Leaflet(LeafletDto dto) {
        this.store = dto.storeName();
        this.url = dto.leafletLink();
        this.imageUrl = dto.imageUrl();
        this.validUntil = dto.validUntil();
        this.pages = dto.leafletsURL() == null ? List.of() : dto.leafletsURL();
        this.downloadDate = dto.downloadDate() != null ? dto.downloadDate() : null;
    }
}
