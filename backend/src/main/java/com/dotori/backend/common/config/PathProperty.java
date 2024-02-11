package com.dotori.backend.common.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import lombok.Getter;

@Getter
@Component
public class PathProperty {
	@Value("${dotori.domain}")
	private String DOMAIN;
}
