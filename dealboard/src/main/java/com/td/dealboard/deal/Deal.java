package com.td.dealboard.deal;

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

    @Column(nullable = false)
    private String store;

    @Column(nullable = false)
    private String category;

    @Column(nullable = false)
    private String categoryCode;

    private Double priceValue;
    private String priceAlt;
    private String unit;
    private Integer discountPercentage;
    private String promoNotes;
    private LocalDate validSince;
    private LocalDate validUntil;
}
