package com.dotori.backend.domain.member.service;

import java.util.Arrays;
import java.util.Date;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.dotori.backend.domain.member.repository.MemberRepository;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Getter
@Slf4j
public class JwtService {

	@Value("${jwt.secretKey}")
	private String secretKey;

	@Value("${jwt.access.expiration}")
	private Long accessTokenExpirationPeriod;

	@Value("${jwt.refresh.expiration}")
	private Long refreshTokenExpirationPeriod;

	@Value("${jwt.access.header}")
	private String accessHeader;

	@Value("${jwt.refresh.header}")
	private String refreshHeader;

	private static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
	private static final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
	private static final String EMAIL_CLAIM = "email";
	private static final String ROLE_CLAIM = "role";
	private static final String BEARER = "Bearer ";

	private final MemberRepository memberRepository;
	private final RedisService redisService;

	/**
	 * AccessToken 생성
	 */
	public String createAccessToken(String email, String role) {
		Date now = new Date();
		return JWT.create()
			.withSubject(ACCESS_TOKEN_SUBJECT)
			.withExpiresAt(new Date(now.getTime() + accessTokenExpirationPeriod)) // 토큰 만료 시간 설정
			.withClaim(EMAIL_CLAIM, email)
			.withClaim(ROLE_CLAIM, "ROLE_" + role)
			.sign(Algorithm.HMAC512(secretKey));
	}

	/**
	 * RefreshToken 생성
	 */
	public String createRefreshToken(String email, String role) {
		Date now = new Date();
		return JWT.create()
			.withSubject(REFRESH_TOKEN_SUBJECT)
			.withExpiresAt(new Date(now.getTime() + refreshTokenExpirationPeriod))
			.withClaim(EMAIL_CLAIM, email)
			.withClaim(ROLE_CLAIM, "ROLE_" + role)
			.sign(Algorithm.HMAC512(secretKey));
	}

	/**
	 * AccessToken 쿠키로보내기
	 */
	public void sendAccessToken(HttpServletResponse response, String accessToken) {
		ResponseCookie cookie = ResponseCookie.from("accessToken", accessToken)
			.httpOnly(true) // JavaScript 접근 방지
			// .secure(true) // HTTPS에서만 전송
			.path("/") // 쿠키 경로
			.sameSite("Lax") // SameSite 설정
			.build(); // 쿠키 생성

		response.addHeader("Set-Cookie", cookie.toString()); // 생성된 쿠키를 응답 헤더에 추가
		log.info("AccessToken 쿠키에 설정 완료");
	}

	/**
	 * RefreshToken 쿠키로보내기
	 */
	public void sendRefreshToken(HttpServletResponse response, String refreshToken) {
		ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken)
			.httpOnly(true) // JavaScript 접근 방지
			// .secure(true) // HTTPS에서만 전송
			.path("/api/members/reaccesstoken") // 쿠키 경로
			.sameSite("Lax") // SameSite 설정
			.build(); // 쿠키 생성

		response.addHeader("Set-Cookie", cookie.toString()); // 생성된 쿠키를 응답 헤더에 추가
		log.info("RefreshToken 쿠키에 설정 완료");
	}

	/**
	 * 쿠키에서 AccessToken 추출
	 * 쿠키 배열을 순회하며, "accessToken"이라는 이름의 쿠키 값을 반환
	 */
	public Optional<String> extractAccessToken(HttpServletRequest request) {
		if (request.getCookies() == null) {
			return Optional.empty();
		}

		return Arrays.stream(request.getCookies())
			.filter(cookie -> "accessToken".equals(cookie.getName()))
			.findFirst()
			.map(Cookie::getValue);
	}

	public Optional<String> extractRefreshToken(HttpServletRequest request) {
		if (request.getCookies() == null) {
			return Optional.empty();
		}

		return Arrays.stream(request.getCookies())
			.filter(cookie -> "refreshToken".equals(cookie.getName()))
			.findFirst()
			.map(Cookie::getValue);
	}

	/**
	 * AccessToken에서 Email 추출
	 * 추출 전에 JWT.require()로 검증기 생성
	 * verify로 AceessToken 검증 후
	 * 유효하다면 getClaim()으로 이메일 추출
	 * 유효하지 않다면 빈 Optional 객체 반환
	 */
	public Optional<String> extractEmail(String accessToken) {
		try {
			// 토큰 유효성 검사하는 데에 사용할 알고리즘이 있는 JWT verifier builder 반환
			return Optional.ofNullable(JWT.require(Algorithm.HMAC512(secretKey))
				.build() // 반환된 빌더로 JWT verifier 생성
				.verify(accessToken) // accessToken을 검증하고 유효하지 않다면 예외 발생
				.getClaim(EMAIL_CLAIM) // claim(Email) 가져오기
				.asString());
		} catch (Exception e) {
			log.error("액세스 토큰이 유효하지 않습니다.");
			return Optional.empty();
		}
	}

	public Optional<String> extractRole(String accessToken) {
		try {
			// 토큰 유효성 검사하는 데에 사용할 알고리즘이 있는 JWT verifier builder 반환
			return Optional.ofNullable(JWT.require(Algorithm.HMAC512(secretKey))
				.build()
				.verify(accessToken) // accessToken을 검증하고 유효하지 않다면 예외 발생
				.getClaim(ROLE_CLAIM) // claim(Role) 가져오기
				.asString());
		} catch (Exception e) {
			log.error("액세스 토큰이 유효하지 않습니다.");
			return Optional.empty();
		}
	}

	public Optional<String> extractEmailFromAccessToken(HttpServletRequest request) {
		return extractAccessToken(request)
			.flatMap(this::extractEmail);
	}

	public Optional<String> extractroleFromAccessToken(HttpServletRequest request) {
		return extractAccessToken(request)
			.flatMap(this::extractRole);
	}

	public Optional<String> extractEmailFromRefreshToken(HttpServletRequest request) {
		return extractRefreshToken(request)
			.flatMap(this::extractEmail);
	}

	public Optional<String> extractroleFromRefreshToken(HttpServletRequest request) {
		return extractRefreshToken(request)
			.flatMap(this::extractRole);
	}

	/**
	 * RefreshToken을 Redis에 저장(업데이트)
	 */
	public void updateRefreshToken(String email, String refreshToken) {
		// Redis에 리프레시 토큰 저장
		redisService.saveRefreshToken(email, refreshToken, refreshTokenExpirationPeriod, TimeUnit.MILLISECONDS);
	}

	public boolean isTokenValid(String token) {
		try {
			JWT.require(Algorithm.HMAC512(secretKey)).build().verify(token);
			return true;
		} catch (Exception e) {
			log.error("유효하지 않은 토큰입니다. {}", e.getMessage());
			return false;
		}
	}

	public void removeAccessToken(HttpServletResponse response) {
		Cookie cookie = new Cookie("accessToken", null);
		cookie.setMaxAge(0);
		cookie.setHttpOnly(true);
		cookie.setSecure(true);
		cookie.setPath("/");
		response.addCookie(cookie);
		log.info("AccessToken 쿠키 제거");
	}

	public void removeRefreshToken(HttpServletResponse response) {
		Cookie cookie = new Cookie("refreshToken", null);
		cookie.setMaxAge(0);
		cookie.setHttpOnly(true);
		cookie.setSecure(true);
		cookie.setPath("/");
		response.addCookie(cookie);
		log.info("AccessToken 쿠키 제거");
	}
}