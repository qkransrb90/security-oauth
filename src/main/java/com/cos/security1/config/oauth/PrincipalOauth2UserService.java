package com.cos.security1.config.oauth;

import java.util.Map;
import java.util.NoSuchElementException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.FacebookUserInfo;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.NaverUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
	private UserRepository userRepository;

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		System.out.println("## getClientRegistration: " + userRequest.getClientRegistration());
		System.out.println("## getAccessToken: " + userRequest.getAccessToken().getTokenValue());
		System.out.println("## super.loadUser(userRequest).getAttributes: " + super.loadUser(userRequest).getAttributes());
		
		OAuth2User oauth2User = super.loadUser(userRequest);
		
		OAuth2UserInfo oAuth2UserInfo = null;
		if ("google".equals(userRequest.getClientRegistration().getRegistrationId())) {
			System.out.println("Google-Login");
			oAuth2UserInfo = new GoogleUserInfo(oauth2User.getAttributes());
		} else if ("facebook".equals(userRequest.getClientRegistration().getRegistrationId())) {
			System.out.println("Facebook-Login");
			oAuth2UserInfo = new FacebookUserInfo(oauth2User.getAttributes());
		} else if ("naver".equals(userRequest.getClientRegistration().getRegistrationId())) {
			System.out.println("Naver-Login");
			oAuth2UserInfo = new NaverUserInfo((Map<?, ?>) oauth2User.getAttributes().get("response"));
		} else {
			throw new NoSuchElementException("지원하지 않는 OAuth-Login 입니다.");
		}
		
		String provider = oAuth2UserInfo.getProvider();
		String providerId = oAuth2UserInfo.getProviderId();	
		String username = provider + "_" + providerId;
		String password = bCryptPasswordEncoder.encode(oAuth2UserInfo.getPassword());
		String email = oAuth2UserInfo.getEmail();
		String role = "ROLE_USER";
		
		User user = userRepository.findByUsername(username)
				.orElseGet(() -> join(provider, providerId, username, password, email, role));
		
		return new PrincipalDetails(user, oauth2User.getAttributes());
	}
	
	public User join(String provider, String providerId, String username, String password, String email, String role) {
		User user = User.builder()
				.provider(provider)
				.providerId(providerId)
				.username(username)
				.password(password)
				.email(email)
				.role(role)
				.build();
		return userRepository.save(user);
	}
}
