package com.td.dealboard.admin.dto;

import java.time.LocalDateTime;

public record AdminUserDto(
     Long id,
     String name,
     String email,
     String role,
     LocalDateTime createdAt
){}

