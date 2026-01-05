package com.td.dealboard.shop;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "shop_locations")
public class ShopLocation {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String storeName;

    // PostGIS geometry type
    @Column(columnDefinition = "geography(Point,4326)")
    private String locationGeom; // W formacie WKT: "POINT(lon lat)"
}
