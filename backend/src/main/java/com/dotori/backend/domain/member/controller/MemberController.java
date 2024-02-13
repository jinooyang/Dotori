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
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.dotori.backend.domain.member.model.dto.GetMemberVideosResponse;
import com.dotori.backend.domain.member.model.dto.ProfileImageUpdateRequest;
import com.dotori.backend.domain.member.model.dto.ProfileImageUpdateResponse;
import com.dotori.backend.domain.member.model.entity.Member;
import com.dotori.backend.domain.member.repository.MemberRepository;
import com.dotori.backend.domain.member.service.JwtService;
import com.dotori.backend.domain.member.service.MemberService;
import com.dotori.backend.domain.member.service.RedisService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/members")
@RequiredArgsConstructor
public class MemberController {

	private final JwtService jwtService;
	private final MemberRepository memberRepository;
	private final RedisService redisService;
	private final MemberService memberService;

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

	@GetMapping("/{memberId}/videos")
	public ResponseEntity<GetMemberVideosResponse> getMemberVideos(@PathVariable(name = "memberId") Long memberId) {

		return ResponseEntity.ok().body(new GetMemberVideosResponse(memberService.getMemberVideos(memberId)));
	}

	@GetMapping("/reaccesstoken")
	public ResponseEntity<?> reAccessToken(HttpServletRequest request, HttpServletResponse response) throws
		IOException {

		String refreshToken = jwtService.extractRefreshToken(request).orElse(null);

		Optional<String> jwtemail = jwtService.extractEmailFromRefreshToken(request);
		Optional<String> jwtrole = jwtService.extractroleFromRefreshToken(request);
		String email = jwtemail.get();
		String role = jwtrole.get();
		log.info("role:{}", role);

		String redisrefreshToken = redisService.getRefreshToken(email).get();
		log.info("refreshToken:{}", refreshToken);
		log.info("redisrefreshToken:{}", redisrefreshToken);
		if (redisrefreshToken != null) {
			if (redisService.isBlacklisted(redisrefreshToken)) {
				response.sendError(HttpStatus.UNAUTHORIZED.value(), "만료된 refresh 토큰입니다. 다시로그인해주세요");
			} else {
				if (refreshToken.equals(redisrefreshToken)) {
					String accessToken = jwtService.createAccessToken(email, "USER"); //서비스확장시 role 부여수정필요
					jwtService.sendAccessToken(response, accessToken);
					return ResponseEntity.ok("accessToken:" + accessToken);
				} else {
					return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
						.body("유효하지않은 접근입니다. 다시 로그인해주세요.");
				}
			}
		} else {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
				.body("만료된 refresh 토큰입니다. 다시 로그인해주세요.");
		}
		return ResponseEntity.ok("ok");
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

	@PutMapping(value = "/profile-image")
	public ResponseEntity<ProfileImageUpdateResponse> updateProfileImg(HttpServletRequest request,
		@Validated ProfileImageUpdateRequest profileImageUpdateRequest) {
		// JWT에서 이메일 추출
		Optional<String> emailOpt = jwtService.extractEmailFromAccessToken(request);

		return ResponseEntity.ok()
			.body(new ProfileImageUpdateResponse(
				memberService.updateProfileImage(emailOpt.get(), profileImageUpdateRequest)));
	}

}
