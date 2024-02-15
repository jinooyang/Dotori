package com.dotori.backend.domain.video.model.entity;

import static javax.persistence.GenerationType.*;
import static lombok.AccessLevel.*;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

import com.dotori.backend.common.entity.BaseTimeEntity;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = PROTECTED)
@Table(name = "video")
public class Video extends BaseTimeEntity {
	@Id
	@GeneratedValue(strategy = IDENTITY)
	@Column(name = "video_id")
	private Long videoId;

	@Column(length = 100, name = "path")
	private String path;

	@Builder
	public Video(Long videoId, String path) {
		this.videoId = videoId;
		this.path = path;
	}

	@Builder
	public Video(String path) {
		this.path = path;
	}
}
