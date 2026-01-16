package com.td.dealboard.admin;

public record AdminDealDto (
     Long id,
     String name,
     String store,
     String category,
     String promoNotes,
     Double priceValue,
     String priceAlt,
     Double discountPercentage,
     String imageUrl,
     String unit,
     String validUntil,
     String validSince,
     Boolean appRequired
){}