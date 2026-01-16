package com.td.dealboard.data;

import com.td.dealboard.user.Role;
import com.td.dealboard.user.User;
import com.td.dealboard.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class UserDataInitializer {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Bean
    public CommandLineRunner initUsers() {
        return args -> {
            String adminEmail = "admin@example.com";
            String userEmail = "user@example.com";

            if (!userRepository.existsByEmail(adminEmail)) {
                User user = new User();
                user.setEmail(adminEmail);
                user.setPassword(passwordEncoder.encode("Admin123"));
                user.setRole(Role.ADMIN);

                userRepository.save(user);
            }
            if (!userRepository.existsByEmail(userEmail)) {
                User user = new User();
                user.setEmail(userEmail);
                user.setPassword(passwordEncoder.encode("User123"));
                user.setRole(Role.USER);

                userRepository.save(user);
            }
        };
    }
}
