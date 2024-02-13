package com.dotori.backend.domain.member.service;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.dotori.backend.domain.member.model.Enum.SocialType;
import com.dotori.backend.domain.member.model.dto.auth.CustomOAuth2User;
import com.dotori.backend.domain.member.model.dto.auth.OAuth2Attributes;
import com.dotori.backend.domain.member.model.entity.Member;
import com.dotori.backend.domain.member.repository.MemberRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

	private final MemberRepository memberRepository;

	private static final String NAVER = "naver";
	private static final String KAKAO = "kakao";

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		log.info("CustomOAuth2UserService.loadUser() 실행 - OAuth2 로그인 요청 진입");

		/**
		 * DefaultOAuth2UserService 객체를 생성하여, loadUser(userRequest)를 통해 DefaultOAuth2User 객체를 생성 후 반환
		 * DefaultOAuth2UserService의 loadUser()는 소셜 로그인 API의 사용자 정보 제공 URI로 요청을 보내서
		 * 사용자 정보를 얻은 후, 이를 통해 DefaultOAuth2User 객체를 생성 후 반환한다.
		 * 결과적으로, OAuth2User는 OAuth 서비스에서 가져온 유저 정보를 담고 있는 유저
		 */
		OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
		OAuth2User oAuth2User = delegate.loadUser(userRequest);
		/**
		 * userRequest에서 registrationId 추출 후 registrationId으로 SocialType 저장
		 * http://localhost:8080/oauth2/authorization/kakao에서 kakao가 registrationId
		 * userNameAttributeName은 이후에 nameAttributeKey로 설정된다.
		 */
		String registrationId = userRequest.getClientRegistration().getRegistrationId();
		SocialType socialType = getSocialType(registrationId);
		String userNameAttributeName = userRequest.getClientRegistration()
			.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
		Map<String, Object> attributes = oAuth2User.getAttributes(); // 소셜 로그인에서 API가 제공하는 userInfo의 Json 값(유저 정보들)

		// socialType에 따라 유저 정보를 통해 OAuthAttributes 객체 생성
		OAuth2Attributes extractAttributes = OAuth2Attributes.of(socialType, userNameAttributeName, attributes);

		Member createdUser = getUser(extractAttributes, socialType); // getUser() 메소드로 User 객체 생성 후 반환

		// DefaultOAuth2User를 구현한 CustomOAuth2User 객체를 생성해서 반환
		return new CustomOAuth2User(
			Collections.singleton(new SimpleGrantedAuthority(createdUser.getRole().getKey())),
			attributes,
			extractAttributes.getNameAttributeKey(),
			createdUser.getMemberId(),
			createdUser.getEmail(),
			createdUser.getRole(),
			createdUser.getRefreshToken()
		);
	}

	private SocialType getSocialType(String registrationId) {
		if (NAVER.equals(registrationId)) {
			return SocialType.NAVER;
		}
		if (KAKAO.equals(registrationId)) {
			return SocialType.KAKAO;
		}
		return SocialType.GOOGLE;
	}

	private Member getUser(OAuth2Attributes attributes, SocialType socialType) {
		Optional<Member> existingMember = memberRepository.findByEmail(attributes.getOauth2UserInfo().getEmail());

		if (existingMember.isPresent()) {
			// 기존 사용자가 존재하면 기존 사용자 정보를 그대로 반환
			return existingMember.get();
		} else {
			// 새로운 사용자인 경우 사용자를 생성하고 저장
			return saveUser(attributes, socialType);
		}
	}

	/**
	 * OAuthAttributes의 toEntity() 메소드를 통해 빌더로 User 객체 생성 후 반환
	 * 생성된 User 객체를 DB에 저장 : socialType, socialId, email, role 값만 있는 상태
	 */
	private Member saveUser(OAuth2Attributes attributes, SocialType socialType) {
		Member createdUser = attributes.toEntity(socialType, attributes.getOauth2UserInfo());
		return memberRepository.save(createdUser);
	}
}