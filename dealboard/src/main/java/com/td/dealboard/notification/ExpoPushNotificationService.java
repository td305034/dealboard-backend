package com.td.dealboard.notification;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class ExpoPushNotificationService {

    private static final String EXPO_PUSH_URL = "https://exp.host/--/api/v2/push/send";
    private final RestTemplate restTemplate;

    public void sendNotification(String expoPushToken, String title, String body, Map<String, Object> data) {
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

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Map<String, Object>> request = new HttpEntity<>(notification, headers);

            ResponseEntity<String> response = restTemplate.postForEntity(
                    EXPO_PUSH_URL,
                    request,
                    String.class
            );

            if (response.getStatusCode().is2xxSuccessful()) {
                System.out.println("Notification sent successfully to: " + expoPushToken);
            } else {
                System.err.println("Failed to send notification: " + response.getStatusCode());
            }
        } catch (Exception e) {
            System.err.println("Error sending notification to " + expoPushToken + ": " + e.getMessage());
        }
    }
}