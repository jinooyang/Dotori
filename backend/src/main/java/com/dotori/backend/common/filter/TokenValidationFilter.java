package com.dotori.backend.common.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

import com.dotori.backend.domain.member.service.JwtService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class TokenValidationFilter extends OncePerRequestFilter {

	private final JwtService jwtService;
	private static final String NO_CHECK_URL = "/reaccesstoken";

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {

		if (request.getRequestURI().contains(NO_CHECK_URL)) {
			filterChain.doFilter(request, response);
			return;
		}

		String accessToken = jwtService.extractAccessToken(request).orElse(null);
		if (accessToken != null && !jwtService.isTokenValid(accessToken)) {
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			response.getWriter().write("{\"error\": \"Access Token is invalid\"}");
			response.setContentType("application/json");
			return;
		}

		filterChain.doFilter(request, response);
	}
}
