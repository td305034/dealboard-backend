package com.td.dealboard.user;

import com.fasterxml.jackson.annotation.JsonProperty;

public record NotificationTimeDto(
        @JsonProperty("notificationTime") NotificationTime time
) {}
