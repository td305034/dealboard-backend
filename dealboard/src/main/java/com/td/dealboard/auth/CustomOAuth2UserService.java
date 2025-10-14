package com.td.dealboard.auth;

import com.td.dealboard.user.AuthProvider;
import com.td.dealboard.user.Role;
import com.td.dealboard.user.User;
import com.td.dealboard.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String email = oAuth2User.getAttribute("email");
        String firstName = oAuth2User.getAttribute("given_name");
        String lastName = oAuth2User.getAttribute("family_name");

        userRepository.findByEmail(email).ifPresentOrElse(
                user -> {
                    if (user.getProvider() != AuthProvider.GOOGLE) {
                        throw new RuntimeException("Email registered locally, please login using password.");
                    }
                },
                () -> {
                    User newUser = User.builder()
                            .email(email)
                            .firstName(firstName)
                            .lastName(lastName)
                            .role(Role.USER)
                            .provider(AuthProvider.GOOGLE)
                            .build();
                    userRepository.save(newUser);
                }
        );

        return oAuth2User;
    }
}
