package com.td.dealboard.auth;

import lombok.Builder;

@Builder
public record AuthenticationResponse(
     String accessToken,
     String refreshToken
){}
