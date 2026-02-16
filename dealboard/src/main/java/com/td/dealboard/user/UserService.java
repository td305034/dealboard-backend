package com.td.dealboard.user;

import com.td.dealboard.auth.AuthenticationService;
import com.td.dealboard.auth.JwtService;
import com.td.dealboard.user.dto.NotificationTimeDto;
import com.td.dealboard.user.dto.request.PushTokenRequest;
import com.td.dealboard.user.dto.TrackedProductsDto;
import com.td.dealboard.user.dto.TrackedStoresDto;
import com.td.dealboard.user.dto.request.ToggleNotificationRequest;
import com.td.dealboard.user.dto.response.ToggleNotificationResponse;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final AuthenticationService authenticationService;
    private final JwtService jwtService;

    @Transactional
    public void addPushToken(String email, PushTokenRequest req) {
        User user = userRepository.findByEmail(email).orElseThrow();
        user.getPushTokens().add(req.pushToken());
        userRepository.save(user);
    }

    @Transactional
    public void removePushToken(String email, PushTokenRequest req) {
        User user = userRepository.findByEmail(email).orElseThrow(() -> new EntityNotFoundException("User with email " + email + " not found"));
        user.getPushTokens().remove(req.pushToken());
        userRepository.save(user);
    }

    @Transactional
    public ToggleNotificationResponse toggleNotification(String email, ToggleNotificationRequest req) {
        User user = userRepository.findByEmail(email).orElseThrow(() -> new EntityNotFoundException("User with email " + email + " not found"));

        if (user.getNotifications() == null) {user.setNotifications(new HashMap<>());}
        String productName = req.productName();
        Boolean active = req.active();

        if(!active) {
            user.getNotifications().remove(productName);
            userRepository.save(user);
            return new ToggleNotificationResponse("Notification removed for product: " + productName);
        }else{
            user.getNotifications().put(productName, new Date());
            userRepository.save(user);
            return new ToggleNotificationResponse("Notification added for product: " + productName);
        }
    }

    @Transactional
    public String changeName(String email, String name) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("User with email " + email + " not found"));
        user.setName(name);
        userRepository.save(user);
        return authenticationService.createAccessToken(user);
    }

    @Transactional(readOnly = true)
    public Set<String> getSelectedStores(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(()->new EntityNotFoundException("Użytkownik o emailu " + email + " nie istnieje"));
        return user.getSelectedStores();
    }

    @Transactional(readOnly = true)
    public Set<String> getSelectedProducts(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(()->new EntityNotFoundException("Użytkownik o emailu " + email + " nie istnieje"));
        return user.getSelectedProducts();
    }

    @Transactional
    public void changeNotificationTime(String email, NotificationTimeDto req) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(()->new EntityNotFoundException("Użytkownik o emailu " + email + " nie istnieje"));
        user.setNotificationTime(req.time());
        userRepository.save(user);
    }

    @Transactional
    public void updateTrackedProducts(String email, TrackedProductsDto req) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("User with email " + email + " not found"));
        user.setSelectedProducts(req.trackedProducts());
        userRepository.save(user);
    }

    @Transactional
    public void updateTrackedStores(String email, TrackedStoresDto req) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User with email " + email + " not found"));
        user.setSelectedStores(new HashSet<>(req.trackedStores()));
        userRepository.save(user);
    }

    public String completeOnboarding(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User with email " + email + " not found"));
        user.setOnboardingCompleted(true);
        userRepository.save(user);
        Map<String, Object> userInfoWithoutExp = authenticationService.createUserInfoWithoutExp(user);

        return jwtService.generateToken(userInfoWithoutExp, user);
    }
}
