package com.td.dealboard.notification;

import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class ExpoPushNotificationService {

    private static final String EXPO_PUSH_URL = "https://exp.host/--/api/v2/push/send";

    private final WebClient webClient;

    public void sendNotification(
            String expoPushToken,
            String title,
            String body,
            Map<String, Object> data
    ) {
        try {
            Map<String, Object> notification = new HashMap<>();
            notification.put("to", expoPushToken);
            notification.put("title", title);
            notification.put("body", body);
            notification.put("sound", "default");
            notification.put("priority", "high");

            if (data != null) {
                notification.put("data", data);
            }

            ResponseEntity<String> response = webClient.post()
                    .uri(EXPO_PUSH_URL)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(notification)
                    .retrieve()
                    .toEntity(String.class)
                    .block();

            if (response != null && response.getStatusCode().is2xxSuccessful()) {
                System.out.println("Notification sent successfully to: " + expoPushToken);
            } else {
                System.err.println("Failed to send notification to: " + expoPushToken);
            }

        } catch (WebClientResponseException e) {
            System.err.println("Expo API error (" + e.getStatusCode() + "): " + e.getResponseBodyAsString());
        } catch (Exception e) {
            System.err.println("Error sending notification to " + expoPushToken + ": " + e.getMessage());
        }
    }
}
