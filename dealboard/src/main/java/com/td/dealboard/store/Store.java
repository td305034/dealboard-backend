package com.td.dealboard.store;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;

import java.util.Locale;

@Data
@Builder
@AllArgsConstructor
@RequiredArgsConstructor
@Entity
@Table(name = "stores", uniqueConstraints = @UniqueConstraint(name = "uq_stores_name_url", columnNames = {"name", "url"}))
public class Store {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String url;
}
