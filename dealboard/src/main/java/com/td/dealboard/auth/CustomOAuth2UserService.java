package com.td.dealboard.auth;

import com.td.dealboard.user.AuthProvider;
import com.td.dealboard.user.User;
import com.td.dealboard.user.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    public CustomOAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String email = oAuth2User.getAttribute("email");
        if (email == null || email.isBlank()) {
            throw new OAuth2AuthenticationException("Brak adresu email w profilu Google");
        }

        User user = userRepository.findByEmail(email)
                .map(u -> updateExistingUser(u, oAuth2User))
                .orElseGet(() -> registerNewUser(oAuth2User));

        Collection<? extends GrantedAuthority> authorities =
                List.of(new SimpleGrantedAuthority("ROLE_USER"));

        return new DefaultOAuth2User(authorities, oAuth2User.getAttributes(), "sub");
    }

    private User registerNewUser(OAuth2User oAuth2User) {
        User u = new User();
        u.setEmail(oAuth2User.getAttribute("email"));
        u.setFirstName(oAuth2User.getAttribute("name"));
        u.setProvider(AuthProvider.GOOGLE);
        return userRepository.save(u);
    }

    private User updateExistingUser(User u, OAuth2User oAuth2User) {
        u.setFirstName(oAuth2User.getAttribute("name"));
        return userRepository.save(u);
    }
}
