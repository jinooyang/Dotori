package com.dotori.backend.domain.room.model.entity;

import static javax.persistence.CascadeType.*;
import static javax.persistence.FetchType.*;
import static javax.persistence.GenerationType.*;
import static lombok.AccessLevel.*;

import java.util.ArrayList;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import com.dotori.backend.common.entity.BaseTimeEntity;
import com.dotori.backend.domain.book.model.entity.Book;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@NoArgsConstructor(access = PROTECTED)
@Table(name = "room")
public class Room extends BaseTimeEntity {
	@Id
	@Column(name = "room_id")
	@GeneratedValue(strategy = IDENTITY) // auto_increment
	private Long roomId;

	@ManyToOne
	@JoinColumn(name = "book_id", nullable = false)
	private Book book;

	@OneToMany(mappedBy = "room", cascade = ALL)
	private List<RoomMember> roomMembers = new ArrayList<>();

	@Column(name = "host_id")
	private Long hostId;

	@Column(length = 20, name = "title")
	private String title;

	@Column(length = 50, name = "password")
	private String password;

	@Setter
	@Column(name = "is_recording")
	private Boolean isRecording;

	@Setter
	@Column(name = "join_cnt")
	private int joinCnt;

	@Column(name = "limit_cnt")
	private int limitCnt;

	@Column(name = "is_public")
	private Boolean isPublic;

	@Column(length = 50, name = "session_id")
	private String sessionId;

	@Builder
	public Room(Book book, List<RoomMember> roomMembers, Long hostId, String title, String password,
		Boolean isRecording, Integer joinCnt, Integer limitCnt, Boolean isPublic, String sessionId) {
		this.book = book;
		this.roomMembers = roomMembers;
		this.hostId = hostId;
		this.title = title;
		this.password = password;
		this.isRecording = isRecording;
		this.joinCnt = joinCnt;
		this.limitCnt = limitCnt;
		this.isPublic = isPublic;
		this.sessionId = sessionId;
	}

}
