package com.dotori.backend.domain.member.model.dto.auth;

import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import com.dotori.backend.domain.member.model.Enum.Role;

import lombok.Getter;

/**
 * DefaultOAuth2User를 상속하고, email과 role 필드를 추가로 가진다.
 */
@Getter
public class CustomOAuth2User extends DefaultOAuth2User {

	private final Long memberId;
	private final String email;
	private final Role role;
	private final String refreshtoken;

	public CustomOAuth2User(Collection<? extends GrantedAuthority> authorities,
		Map<String, Object> attributes, String nameAttributeKey, Long memberId,
		String email, Role role, String refreshtoken) {
		super(authorities, attributes, nameAttributeKey);
		this.memberId = memberId;
		this.email = email;
		this.role = role;
		this.refreshtoken = refreshtoken;
	}
}