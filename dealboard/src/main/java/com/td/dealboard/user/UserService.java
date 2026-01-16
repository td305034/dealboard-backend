package com.td.dealboard.user;

import com.td.dealboard.auth.AuthenticationService;
import com.td.dealboard.exceptions.ApiException;
import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final AuthenticationService authenticationService;

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

    public String changeName(String email, String name) {
        User updatableUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new ApiException("User doesn't exist", HttpStatus.NOT_FOUND));
        updatableUser.setName(name);
        userRepository.save(updatableUser);
        return authenticationService.createAccessToken(updatableUser);
    }

    public Set<String> getSelectedStores(String email) {
        User updatableUser = userRepository.findByEmail(email)
                .orElseThrow(()->new ApiException("Uzytkownik nie istnieje", HttpStatus.NOT_FOUND));
        return updatableUser.getSelectedStores();
    }

    public Set<String> getSelectedProducts(String email) {
        User updatableUser = userRepository.findByEmail(email)
                .orElseThrow(()->new ApiException("Uzytkownik nie istnieje", HttpStatus.NOT_FOUND));
        return updatableUser.getSelectedProducts();
    }

    public void changeNotificationTime(String email, NotificationTime time) {
        User updatableUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        updatableUser.setNotificationTime(time);
        userRepository.save(updatableUser);
    }
}
