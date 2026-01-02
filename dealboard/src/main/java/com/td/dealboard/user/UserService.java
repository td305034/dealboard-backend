package com.td.dealboard.user;

import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    @Transactional
    public void addPushToken(String email, String pushToken) {
        User user = userRepository.findByEmail(email).orElseThrow();
        user.getPushTokens().add(pushToken);
        userRepository.save(user);
    }

    @Transactional
    public void removePushToken(String email, String pushToken) {
        User user = userRepository.findByEmail(email).orElseThrow();
        user.getPushTokens().remove(pushToken);
        userRepository.save(user);
    }

    public ResponseEntity<Map<String, String>> toggleNotification(String email, String productName, Boolean active) {
        User updatableUser = userRepository.findByEmail(email).orElseThrow();
        if(!active) {
            updatableUser.getNotifications().remove(productName);
            userRepository.save(updatableUser);
            return ResponseEntity.ok(Map.of(
                    "message", "Notification removed for product: " + productName
            ));
        }else{
            updatableUser.getNotifications().put(productName, new Date());
            userRepository.save(updatableUser);
            return ResponseEntity.ok(Map.of(
                    "message", "Notification added for product: " + productName
            ));
        }
    }
}
