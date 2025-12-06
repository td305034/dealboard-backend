package com.td.dealboard.deal;

import jakarta.persistence.*;
import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name="deal")
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

    private String description;
    private Double price;
    private Integer discountPercentage;

    private String imageUrl;

}
