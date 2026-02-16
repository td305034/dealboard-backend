package com.td.dealboard.user.dto.request;

import jakarta.validation.constraints.NotNull;

public record PushTokenRequest(
    @NotNull
    String pushToken
) { }
