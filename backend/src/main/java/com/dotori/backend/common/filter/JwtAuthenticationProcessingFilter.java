package com.dotori.backend.common.filter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.dotori.backend.domain.member.model.entity.Member;
import com.dotori.backend.domain.member.repository.MemberRepository;
import com.dotori.backend.domain.member.service.JwtService;
import com.dotori.backend.domain.member.service.RedisService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Jwt 인증 필터
 * 기본적으로 사용자는 요청 헤더에 AccessToken만 담아서 요청
 * AccessToken 만료 시에만 RefreshToken을 AccessToken과 함께 보냄
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationProcessingFilter extends OncePerRequestFilter {
	private final JwtService jwtService;
	private final MemberRepository memberRepository;
	private final RedisService redisService;
	private static final String NO_CHECK_URL = "/reaccesstoken";

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {
		log.info("경로확인로그: {}", request.getRequestURI());
		if (request.getRequestURI().contains(NO_CHECK_URL)) {
			filterChain.doFilter(request, response);
			return; // return으로 이후 현재 필터 진행 막기 (안해주면 아래로 내려가서 계속 필터 진행시킴)
		}

		// accesstoken 만료여부체크
		String accessToken = jwtService.extractAccessToken(request).orElse(null);
		if (accessToken != null) { //accesstoken이 있으면
			Optional<String> email = jwtService.extractEmailFromAccessToken(request);
			Optional<String> role = jwtService.extractroleFromAccessToken(request);
			log.info("email:{}", email);
			log.info("role:{}", role);
			if (email.isPresent() && role.isPresent()) {
				Member member = memberRepository.findByEmail(email.get()).orElse(null);
				SimpleGrantedAuthority authority = new SimpleGrantedAuthority(role.get());
				List<GrantedAuthority> authorities = Collections.singletonList(authority);

				// Authentication 객체 생성
				Authentication authentication = new UsernamePasswordAuthenticationToken(member, null, authorities);
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
			filterChain.doFilter(request, response);
		} else {
			filterChain.doFilter(request, response);
		}

	}

}