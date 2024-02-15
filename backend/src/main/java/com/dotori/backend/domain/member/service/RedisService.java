package com.dotori.backend.domain.member.service;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class RedisService {

	private final RedisTemplate<String, String> redisTemplate;
	private static final String REFRESH_TOKEN_KEY_PREFIX = "refreshToken:";
	private static final String BLACKLIST_PREFIX = "blacklist:";
	private static final long TRACKING_USER_EXPIRE_TIME = 15 * 60 * 1000L;    // 15분

	public boolean checkDuplicateLogins(String email) {
		return redisTemplate.opsForValue().get(REFRESH_TOKEN_KEY_PREFIX + email) != null;
	}

	public void saveRefreshToken(String email, String refreshToken, long duration, TimeUnit timeUnit) {
		String key = REFRESH_TOKEN_KEY_PREFIX + email;
		redisTemplate.opsForValue().set(key, refreshToken, duration, timeUnit);
		log.info("RefreshToken saved in Redis for email: {}", email);
	}

	public Optional<String> getRefreshToken(String email) {
		String key = REFRESH_TOKEN_KEY_PREFIX + email;
		return Optional.ofNullable(redisTemplate.opsForValue().get(key));
	}

	public void removeRefreshToken(String email) {
		String key = REFRESH_TOKEN_KEY_PREFIX + email;
		redisTemplate.delete(key);
		log.info("RefreshToken removed from Redis for email: {}", email);
	}

	// 블랙리스트에 토큰 추가
	public void addToBlacklist(String refreshToken) {
		redisTemplate.opsForSet().add(BLACKLIST_PREFIX, refreshToken);
	}

	// 블랙리스트에 토큰이 있는지 확인
	public boolean isBlacklisted(String refreshToken) {
		return redisTemplate.opsForSet().isMember(BLACKLIST_PREFIX, refreshToken);
	}

	//트래킹부분
	public void saveTrackingUserSession(String email, String token) {
		if (email.equals("ssafy@gmail.com"))
			return; //관리자 권한은 중복 허용

		// 토큰 비교해서 같은 이용자는 유효시간 갱신
		// 토큰 날아가면 갱신 불가
		if (!checkDuplicateLogins(email) || token.equals(
			redisTemplate.opsForValue().get(REFRESH_TOKEN_KEY_PREFIX + email)))
			redisTemplate.opsForValue()
				.set(REFRESH_TOKEN_KEY_PREFIX + email, token, TRACKING_USER_EXPIRE_TIME, TimeUnit.MILLISECONDS);
		else
			log.info("현재 이용할 수 없습니다.");
	}

	public void removeTrackingUserSession(String email, String token) {
		if (token.equals(redisTemplate.opsForValue().get(REFRESH_TOKEN_KEY_PREFIX + email)))
			redisTemplate.delete(REFRESH_TOKEN_KEY_PREFIX + email);
	}
}