package com.td.dealboard.deal;

import com.td.dealboard.store.Store;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name="deals")
public class Deal {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @ManyToOne
    @JoinColumn(name = "store_id", nullable = false)
    private Store store;

    @Column(nullable = false)
    private String category;

    @Column(nullable = false)
    private String categoryCode;

    private Double priceValue;
    private String priceAlt;

    @Column(nullable = false)
    private String unit;

    private Integer discountPercentage;
    private String promoNotes;
    private LocalDate validSince;

    @Column(nullable = false)
    private LocalDate validUntil;
}
