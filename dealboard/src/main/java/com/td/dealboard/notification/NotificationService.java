package com.td.dealboard.notification;

import com.td.dealboard.deal.Deal;
import com.td.dealboard.deal.DealRepository;
import com.td.dealboard.user.User;
import com.td.dealboard.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Transactional
@RequiredArgsConstructor
public class NotificationService {

    private final UserRepository userRepo;
    private final DealRepository dealRepo;
    private final ExpoPushNotificationService pushService;


    public void addTrackedProduct(User user, String productKeyword) {
        // Dodaj do trackedProducts
        user.getSelectedProducts().add(productKeyword);
        // Inicjalizuj w notifications (null = nigdy nie wysłano)
        user.getNotifications().putIfAbsent(productKeyword, null);
        userRepo.save(user);
    }

    public void removeTrackedProduct(User user, String productKeyword) {
        user.getSelectedProducts().remove(productKeyword);
        user.getNotifications().remove(productKeyword);
        userRepo.save(user);
    }

    public Set<String> getTrackedProducts(User user) {
        return user.getSelectedProducts();
    }

    public void registerPushToken(User user, String pushToken) {
        user.getPushTokens().add(pushToken);
        userRepo.save(user);
    }

    @Scheduled(cron = "0 56 11 * * *")
    public void checkDealsAndNotify() {
        List<User> users = userRepo.findAll().stream()
                .filter(u -> !u.getPushTokens().isEmpty())
                .filter(u -> !u.getNotifications().isEmpty())
                .collect(Collectors.toList());

        for (User user : users) {
            try {
                processUserNotifications(user);
            } catch (Exception e) {
                System.err.println("Error processing notifications for user "
                        + user.getId() + ": " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    public void processUserNotifications(User user) {
        Set<String> notificationProducts = user.getNotifications().keySet();
        Map<String, Date> notificationHistory = user.getNotifications();
        List<MatchedDeal> matchedDeals = new ArrayList<>();

        Date now = new Date();
        Date oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

        for (String productKeyword : notificationProducts) {
            Date lastNotificationDate = notificationHistory.get(productKeyword);

            if (lastNotificationDate != null && lastNotificationDate.after(oneDayAgo)) {
                continue;
            }

            String normalizedKeyword = normalizeProductName(productKeyword);

            List<Deal> deals = dealRepo.findAll().stream()
                    .filter(deal -> {
                        String normalizedDealName = normalizeProductName(deal.getName());
                        return normalizedDealName.contains(normalizedKeyword)
                                || normalizedKeyword.contains(normalizedDealName);
                    })
                    .filter(this::isDealActive)
                    .collect(Collectors.toList());

            if (!deals.isEmpty()) {
                matchedDeals.add(new MatchedDeal(productKeyword, deals.get(0)));
            }
        }

        if (matchedDeals.isEmpty()) {
            return;
        }

        sendSmartNotifications(user, matchedDeals);

        for (MatchedDeal matched : matchedDeals) {
            notificationHistory.put(matched.productKeyword, now);
        }
        userRepo.save(user);
    }

    private void sendSmartNotifications(User user, List<MatchedDeal> matchedDeals) {
        Set<String> tokens = user.getPushTokens();
        int numProducts = matchedDeals.size();

        if (numProducts > 6) {
            for (String token : tokens) {
                sendBulkNotification(token, numProducts);
            }
        } else if (numProducts >= 4) {
            for (String token : tokens) {
                sendGroupedNotification(token, matchedDeals);
            }
        } else {
            for (String token : tokens) {
                sendIndividualNotifications(token, matchedDeals);
            }
        }
    }

    private void sendBulkNotification(String token, int count) {
        String title = "🎉 Świetne wieści!";
        String body = String.format("%d produktów, które śledzisz jest na promocji!", count);

        Map<String, Object> data = new HashMap<>();
        data.put("type", "bulk");
        data.put("count", String.valueOf(count));

        pushService.sendNotification(token, title, body, data);
    }

    private void sendGroupedNotification(String token, List<MatchedDeal> matchedDeals) {
        int amount = matchedDeals.size();
        String title = "🔔 Promocje na śledzone produkty!";

        StringBuilder bodyBuilder = new StringBuilder();
        for (int i = 0; i < Math.min(3, amount); i++) {
            Deal deal = matchedDeals.get(i).deal;
            bodyBuilder.append("• ").append(deal.getName());
            if (deal.getPriceValue() != null) {
                bodyBuilder.append(" - ").append(deal.getPriceValue()).append("zł");
            }
            bodyBuilder.append("\n");
        }

        if (amount > 3) {
            bodyBuilder.append("...i ").append(amount - 3).append(" więcej!");
        }

        Map<String, Object> data = new HashMap<>();
        data.put("type", "grouped");
        data.put("count", String.valueOf(matchedDeals.size()));

        pushService.sendNotification(token, title, bodyBuilder.toString().trim(), data);
    }

    private void sendIndividualNotifications(String token, List<MatchedDeal> matchedDeals) {
        for (MatchedDeal matched : matchedDeals) {
            Deal deal = matched.deal;

            String title = "🔔 Promocja znaleziona!";
            String body = String.format(
                    "%s jest teraz w promocji!%s",
                    deal.getName(),
                    deal.getPriceValue() != null ? " Cena: " + deal.getPriceValue() + "zł" : ""
            );

            Map<String, Object> data = new HashMap<>();
            data.put("type", "individual");
            data.put("dealId", String.valueOf(deal.getId()));
            data.put("dealName", deal.getName());

            pushService.sendNotification(token, title, body, data);
        }
    }

    private String normalizeProductName(String name) {
        return name.toLowerCase()
                .replaceAll("[^a-ząćęłńóśźż0-9\\s]", "")
                .replaceAll("\\s+", " ")
                .trim();
    }

    private boolean isDealActive(Deal deal) {
        LocalDate terminationDate = deal.getValidUntil();
        LocalDate now = LocalDate.now();
        if (terminationDate != null) {
            return deal.getValidUntil().isAfter(now);
        }
        return false;
    }

    private static class MatchedDeal {
        String productKeyword;
        Deal deal;

        MatchedDeal(String productKeyword, Deal deal) {
            this.productKeyword = productKeyword;
            this.deal = deal;
        }
    }
}