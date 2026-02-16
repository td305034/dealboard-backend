package com.td.dealboard.scrapper;

import com.td.dealboard.notification.NotificationService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@Component
@RequiredArgsConstructor
@RestController("/api/test")
public class TestController {
    private final PromotionService promotionService;
    private final LeafletProcessingService scrapperService;
    private final NotificationService notificationService;

    @GetMapping("/process-leaflets")
    public void processLeaflets() {
        scrapperService.processLeaflets();
    }

    @GetMapping("/get-leaflets")
    public void getLeaflets() {
        promotionService.fetchLeafletsScheduler();
    }

    @PostMapping("/send-notifications")
    public void sendNotifications() {
        notificationService.checkDealsAndNotifyMorning();
    }
}
