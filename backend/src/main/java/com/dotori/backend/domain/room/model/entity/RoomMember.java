package com.dotori.backend.domain.room.model.entity;

import static javax.persistence.FetchType.*;
import static javax.persistence.GenerationType.*;
import static lombok.AccessLevel.*;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToOne;
import javax.persistence.Table;

import com.dotori.backend.common.entity.BaseTimeEntity;
import com.dotori.backend.domain.member.model.entity.Member;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = PROTECTED)
@Table(name = "room_member")
public class RoomMember extends BaseTimeEntity {
	@Id
	@Column(name = "room_member_id")
	@GeneratedValue(strategy = IDENTITY)
	private Long roomMemberId;

	@Column(name = "role_id")
	private Long roleId;

	@Column(name = "avatar_id")
	private Long avatarId;

	@ManyToOne(fetch = LAZY)
	@JoinColumn(name = "member_id")
	private Member member;

	@ManyToOne(fetch = LAZY)
	@JoinColumn(name = "room_id")
	private Room room;

	@Column(name = "is_ready")
	private boolean isReady;

	@Builder
	public RoomMember(Member member, Room room) {
		this.member = member;
		this.room = room;
	}
}
