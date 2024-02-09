package com.dotori.backend.domain.member.model.entity;

import static javax.persistence.FetchType.*;
import static javax.persistence.GenerationType.*;
import static lombok.AccessLevel.*;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import com.dotori.backend.common.entity.BaseTimeEntity;
import com.dotori.backend.domain.video.model.entity.Video;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = PROTECTED)
@Table(name = "member_video")
public class MemberVideo extends BaseTimeEntity {
	@Id
	@Column(name = "member_video_id")
	@GeneratedValue(strategy = IDENTITY)
	private Long memberVideoId;

	@ManyToOne(fetch = LAZY)
	@JoinColumn(name = "member_id", nullable = false)
	private Member member;

	@ManyToOne(fetch = LAZY, cascade = CascadeType.PERSIST)
	@JoinColumn(name = "video_id", nullable = false)
	private Video video;

	@Column
	private Long bookId;

	@Builder
	public MemberVideo(Member member, Video video, Long bookId) {
		this.member = member;
		this.video = video;
		this.bookId = bookId;
	}
}
