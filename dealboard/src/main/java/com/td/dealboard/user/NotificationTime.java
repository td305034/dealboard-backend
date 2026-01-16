package com.td.dealboard.user;

public enum NotificationTime {
    MORNING("09:00"),
    AFTERNOON("14:00"),
    EVENING("20:00");

    private final String time;

    NotificationTime(String time) {
        this.time = time;
    }

    public String getTime() {  // getter
        return time;
    }
}
