package com.td.dealboard.user.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.td.dealboard.user.enums.NotificationTime;

public record NotificationTimeDto(
        @JsonProperty("notificationTime") NotificationTime time
) {}
