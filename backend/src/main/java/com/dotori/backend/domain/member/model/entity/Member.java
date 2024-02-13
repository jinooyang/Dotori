package com.dotori.backend.domain.member.model.entity;

import static javax.persistence.CascadeType.*;
import static javax.persistence.FetchType.*;
import static javax.persistence.GenerationType.*;
import static lombok.AccessLevel.*;

import java.util.ArrayList;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import com.dotori.backend.common.entity.BaseTimeEntity;
import com.dotori.backend.domain.member.model.Enum.Role;
import com.dotori.backend.domain.member.model.Enum.SocialType;
import com.dotori.backend.domain.room.model.entity.RoomMember;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@Builder
@NoArgsConstructor(access = PROTECTED)
@Table(name = "member")
@AllArgsConstructor
public class Member extends BaseTimeEntity {
	@Id
	@Column(name = "member_id")
	@GeneratedValue(strategy = IDENTITY)
	private Long memberId;

	@Column(name = "member_email")
	private String email; // 이메일

	@Column
	private String nickname;

	@Column(length = 100, name = "profile_img")
	private String profileImg;

	@Column(length = 255, name = "refresh_token")
	private String refreshToken;

	@Enumerated(EnumType.STRING)
	private Role role;

	@Enumerated(EnumType.STRING)
	@Column(name = "social_type")
	private SocialType socialType; // KAKAO, NAVER, GOOGLE

	@Column(name = "social_id")
	private String socialId;

	@OneToMany(fetch = LAZY, mappedBy = "member", cascade = ALL)
	private List<RoomMember> roomMembers = new ArrayList<>();

	// 유저 권한 설정 메소드
	public void authorizeUser() {
		this.role = Role.USER;
	}

	//== 유저 필드 업데이트 ==//
	public void updateNickname(String updateNickname) {
		this.nickname = updateNickname;
	}

	public void updateProfileImg(String updateProfileImg) {
		this.profileImg = updateProfileImg;
	}

	public void updateRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	@Builder
	public Member(Long memberId, String nickname, String profileImg, String refreshToken) {
		this.refreshToken = refreshToken;
		this.nickname = nickname;
		this.profileImg = profileImg;
		this.memberId = memberId;
	}
}

