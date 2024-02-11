package com.dotori.backend.common.config;

import javax.servlet.http.HttpServletResponse;

import org.apache.hc.core5.http.HttpHeaders;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.dotori.backend.common.filter.JwtAuthenticationProcessingFilter;
import com.dotori.backend.common.handler.OAuth2LoginFailureHandler;
import com.dotori.backend.common.handler.OAuth2LoginSuccessHandler;
import com.dotori.backend.domain.member.repository.MemberRepository;
import com.dotori.backend.domain.member.service.CustomOAuth2UserService;
import com.dotori.backend.domain.member.service.JwtService;
import com.dotori.backend.domain.member.service.RedisService;

import lombok.RequiredArgsConstructor;

/**
 * 인증은 CustomJsonUsernamePasswordAuthenticationFilter에서 authenticate()로 인증된 사용자로 처리
 * JwtAuthenticationProcessingFilter는 AccessToken, RefreshToken 재발급
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final JwtService jwtService;
	private final MemberRepository memberRepository;
	private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
	private final OAuth2LoginFailureHandler oAuth2LoginFailureHandler;
	private final CustomOAuth2UserService customOAuth2UserService;
	private final LogoutSuccessHandler OAuth2LogoutSuccessHandler;
	private final RedisService redisService;

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			.cors()
			.and()
			.formLogin()
			.disable() // FormLogin 사용 X
			.httpBasic()
			.disable() // httpBasic 사용 X
			.csrf()
			.disable() // csrf 보안 사용 X
			// .headers()
			// .frameOptions()
			// .disable()
			// .and()

			// 세션없는 stateless 환경
			.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()

			// .addFilterBefore(jwtAuthenticationProcessingFilter(), AnonymousAuthenticationFilter.class)
			// URL별 권한 관리 옵션
			.authorizeRequests()
			.mvcMatchers("*/members/status")
			.permitAll()
			// 기본 페이지, css, image, js 하위 폴더에 있는 자료들은 모두 접근 가능
			.antMatchers(
				"/", "/css/**", "/images/**", "/js/**",
				"/favicon.ico", "/resources/**", "/static/**", "/error",
				"/login/**", "/oauth/**", "/oauth2.0/**"
			)
			.permitAll()
			// // 로그인은 항상 접근가능

			// api 제한
			.antMatchers("/api/members/detail", "/api/members/update_nickname", "/api/members/update_profileimg", "/api/members/{memberId}/videos")
			.hasRole("USER")

			// 페이지접근 제한
			.antMatchers("/my-page", "/my-page/info", "/my-page/collection", "/my-page/avatar")
			.hasRole("USER")
			.anyRequest()
			.authenticated() // 위의 경로 이외에는 모두 인증된 사용자만 접근 가능

			//예외핸들러
			.and()
			.exceptionHandling()
			.authenticationEntryPoint(authenticationEntryPoint())

			//로그아웃
			.and()
			.logout()
			.logoutUrl("/api/members/logout") // 로그아웃 URL 지정
			.logoutSuccessHandler(OAuth2LogoutSuccessHandler)
			.invalidateHttpSession(true) // 세션 무효화
			.deleteCookies("JSESSIONID") // 쿠키 삭제

			.and()
			.addFilterAfter(jwtAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
			//소셜 로그인 설정
			.oauth2Login()

			.successHandler(oAuth2LoginSuccessHandler) // 성공시 Handler 설정
			.failureHandler(oAuth2LoginFailureHandler) // 소셜 로그인 실패 시 핸들러 설정
			.userInfoEndpoint()
			.userService(customOAuth2UserService);   // customUserService 설정

		// 원래 스프링 시큐리티 필터 순서가 LogoutFilter 이후에 로그인 필터 동작
		// 순서 : LogoutFilter -> JwtAuthenticationProcessingFilter -> CustomJsonUsernamePasswordAuthenticationFilter

		return http.build();
	}

	/**
	 * AuthenticationManager 설정 후 등록
	 * PasswordEncoder를 사용하는 AuthenticationProvider 지정 (PasswordEncoder는 위에서 등록한 PasswordEncoder 사용)
	 * FormLogin(기존 스프링 시큐리티 로그인)과 동일하게 DaoAuthenticationProvider 사용
	 * UserDetailsService는 커스텀 LoginService로 등록
	 * 또한, FormLogin과 동일하게 AuthenticationManager로는 구현체인 ProviderManager 사용(return ProviderManager)
	 */

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.addAllowedOriginPattern("*"); // 모든 도메인에서 접근 허용
		configuration.addAllowedMethod("*"); // 모든 HTTP 메소드 허용
		configuration.addAllowedHeader("*"); // 모든 헤더 허용
		configuration.setAllowCredentials(true); // 쿠키 허용
		configuration.addExposedHeader(HttpHeaders.LOCATION); // 특정 헤더 노출
		configuration.addExposedHeader(HttpHeaders.SET_COOKIE); // 쿠키 설정 헤더 노출

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

	private AuthenticationEntryPoint authenticationEntryPoint() {
		return (request, response, authException) -> {
			// 인증되지 않은 사용자의 요청 처리 로직
			// 예: 로그인 페이지로 리다이렉트 또는 오류 메시지 응답
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "접근이 거절되었습니다.");
		};
	}

	@Bean
	public JwtAuthenticationProcessingFilter jwtAuthenticationProcessingFilter() {
		JwtAuthenticationProcessingFilter jwtAuthenticationFilter = new JwtAuthenticationProcessingFilter(jwtService,
			memberRepository, redisService);
		return jwtAuthenticationFilter;
	}

}