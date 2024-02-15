package com.dotori.backend.domain.book;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

@TestConfiguration
public class TestRedisSessionConfig {
	@Value("${spring.redis.host}")
	private String REDIS_HOST;

	@Value("${spring.redis.port}")
	private String REDIS_PORT;

	@Bean
	public RedisConnectionFactory redisConnectionFactory() {
		return new LettuceConnectionFactory(REDIS_HOST, Integer.parseInt(REDIS_PORT));
	}

}