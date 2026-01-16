package com.td.dealboard.scrapper;

import com.td.dealboard.leaflet.Leaflet;
import com.td.dealboard.leaflet.LeafletRepository;
import com.td.dealboard.notification.NotificationService;
import com.td.dealboard.user.User;
import com.td.dealboard.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.core.task.TaskExecutor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.concurrent.Executor;

@Component
@RequiredArgsConstructor
@RestController("/api/test")
public class TestController {
    private final PromotionService promotionService;
    private final LeafletRepository leafletRepository;
    private final TaskExecutor scrapperExecutor;
    private final LeafletProcessingService scrapperService;

    private final NotificationService notificationService;
    private final UserRepository userRepository;

    @GetMapping("/process-leaflets")
    public void processLeaflets() {
        try {
            List<Leaflet> leaflets = leafletRepository.findAll();

            Executor executor = runnable -> scrapperExecutor.execute(runnable);
            scrapperService.processFilesParallel(leaflets, executor, 60);
        } catch (Exception e) {
            System.out.println("Error processing leaflets: " + e.getMessage());
        }
    }

    @GetMapping("/get-leaflets")
    public void getLeaflets() {
        promotionService.fetchLeafletsScheduler();
    }

    @PostMapping("/send-notifications")
    public void sendNotifications(@AuthenticationPrincipal User user) {
        User updatableUser = userRepository.findByEmail(user.getEmail()).orElseThrow();
        notificationService.processUserNotifications(updatableUser);
    }
}
