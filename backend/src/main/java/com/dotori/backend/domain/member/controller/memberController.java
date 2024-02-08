package com.dotori.backend.domain.member.controller;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.persistence.EntityNotFoundException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.dotori.backend.domain.member.model.entity.Member;
import com.dotori.backend.domain.member.repository.MemberRepository;
import com.dotori.backend.domain.member.service.JwtService;
import com.dotori.backend.domain.member.service.RedisService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/members")
@CrossOrigin(origins = "*", allowedHeaders = "*")
@RequiredArgsConstructor
public class memberController {

	private final JwtService jwtService;
	private final MemberRepository memberRepository;

	private final RedisService redisService;

	@GetMapping("/status")
	public ResponseEntity<?> getAuthStatus() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		boolean isAnonymous = authentication instanceof AnonymousAuthenticationToken;
		boolean isAuthenticated = authentication != null && authentication.isAuthenticated() && !isAnonymous;

		return ResponseEntity.ok(Collections.singletonMap("isAuthenticated", isAuthenticated));
	}

	@GetMapping("/detail")
	public ResponseEntity<?> getMemberInfo(HttpServletRequest request) {
		Optional<String> jwtdetail = jwtService.extractEmailFromAccessToken(request);

		if (jwtdetail.isPresent()) {
			Optional<Member> emaildetail = memberRepository.findByEmail(jwtdetail.get());

			if (emaildetail.isPresent()) {
				Member member = emaildetail.get();
				Map<String, Object> memberInfo = new HashMap<>();
				memberInfo.put("nickName", member.getNickname());
				memberInfo.put("email", member.getEmail());
				memberInfo.put("memberId", member.getMemberId());
				memberInfo.put("profileImg", member.getProfileImg());

				return ResponseEntity.ok(memberInfo);
			} else {
				return ResponseEntity.status(404).body("가입된 사용자데이터를 찾을수없습니다.");
			}
		} else {
			return ResponseEntity.status(400).body("유효한 토큰을 찾을수없습니다");
		}
	}

	@PostMapping("/reAccessToken")
	public ResponseEntity<?> reAccessToken(HttpServletResponse response, @RequestParam("email") String email) throws
		IOException {

		String redisrefreshToken = redisService.getRefreshToken(email).get();
		if (redisrefreshToken != null) {
			if (redisService.isBlacklisted(redisrefreshToken)) {
				response.sendError(HttpStatus.UNAUTHORIZED.value(), "만료된 refresh 토큰입니다. 다시로그인해주세요");
			}
			Optional<Member> membertemp = memberRepository.findByEmail(email);
			if (membertemp.isPresent()) {
				String mysqlrefreshToken = membertemp.get().getRefreshToken();
				if (mysqlrefreshToken.equals(redisrefreshToken)) {
					String accessToken = jwtService.createAccessToken(email, "ROLE_USER"); //서비스확장시 role 부여수정필요
					jwtService.sendAccessToken(response, accessToken);
					return ResponseEntity.ok("AccessToken:" + accessToken);
				} else {
					return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
						.body("유효하지않은 접근입니다. 다시 로그인해주세요.");
				}
			} else {
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
					.body("등록된사용자가아닙니다.");
			}

		} else {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
				.body("만료된 refresh 토큰입니다. 다시 로그인해주세요.");
		}

	}

	@PutMapping("/update_nickname")
	public ResponseEntity<?> updateNickname(HttpServletRequest request,
		@RequestParam("newNickname") String newNickname) {
		// JWT에서 이메일 추출
		Optional<String> jwtemail = jwtService.extractEmailFromAccessToken(request);
		if (!jwtemail.isPresent()) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
				.body("유효하지않거나 만료된 토큰입니다.");
		}

		// 사용자 정보 찾기 및 닉네임 업데이트
		String email = jwtemail.get();
		Member member = memberRepository.findByEmail(email)
			.orElseThrow(() -> new EntityNotFoundException("해당이메일은 가입되지않은 이메일입니다: " + email));

		member.updateNickname(newNickname);
		memberRepository.save(member);

		return ResponseEntity.ok("닉네임 변경완료.");
	}

	@PutMapping("/update_profileimg")
	public ResponseEntity<?> updateProfileImg(HttpServletRequest request, @RequestParam String newProfileImg) {
		// JWT에서 이메일 추출
		Optional<String> emailOpt = jwtService.extractEmailFromAccessToken(request);
		if (!emailOpt.isPresent()) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
				.body("유효하지않거나 만료된 토큰입니다.");
		}

		// 사용자 정보 찾기 및 프로필사진 업데이트
		String email = emailOpt.get();
		Member member = memberRepository.findByEmail(email)
			.orElseThrow(() -> new EntityNotFoundException("해당이메일은 가입되지않은 이메일입니다: " + email));

		member.updateProfileImg(newProfileImg);
		memberRepository.save(member);

		return ResponseEntity.ok("프로필사진 변경완료.");
	}

}
