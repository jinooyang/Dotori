package com.dotori.backend.domain.room.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.persistence.EntityNotFoundException;
import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.dotori.backend.domain.book.model.dto.BookDto;
import com.dotori.backend.domain.book.model.entity.Book;
import com.dotori.backend.domain.book.repository.BookRepository;
import com.dotori.backend.domain.member.model.entity.Member;
import com.dotori.backend.domain.member.repository.MemberRepository;
import com.dotori.backend.domain.room.model.dto.RoomDto;
import com.dotori.backend.domain.room.model.dto.RoomInitializationDto;
import com.dotori.backend.domain.room.model.entity.Room;
import com.dotori.backend.domain.room.model.entity.RoomMember;
import com.dotori.backend.domain.room.repository.RoomMemberRepository;
import com.dotori.backend.domain.room.repository.RoomRepository;

import io.openvidu.java.client.Connection;
import io.openvidu.java.client.ConnectionProperties;
import io.openvidu.java.client.OpenVidu;
import io.openvidu.java.client.OpenViduHttpException;
import io.openvidu.java.client.OpenViduJavaClientException;
import io.openvidu.java.client.Session;
import io.openvidu.java.client.SessionProperties;

@Service
@Transactional
public class RoomServiceImpl implements RoomService {

	private final RoomRepository roomRepository;
	private final RoomMemberRepository roomMemberRepository;
	private final BookRepository bookRepository;

	private final MemberRepository memberRepository;

	@Autowired
	public RoomServiceImpl(RoomRepository roomRepository,
		RoomMemberRepository roomMemberRepository,
		BookRepository bookRepository, MemberRepository memberRepository
	) {
		this.roomRepository = roomRepository;
		this.roomMemberRepository = roomMemberRepository;
		this.bookRepository = bookRepository;
		this.memberRepository = memberRepository;
	}

	@Override
	public Map<String, String> createRoom(OpenVidu openvidu, RoomInitializationDto params) throws Exception {
		// 세션을 생성합니다.
		Session session = openvidu.createSession(
			SessionProperties.fromJson(params.getSessionProperties()).build());

		if (session == null)
			throw new RuntimeException("세션 생성 중 문제 발생");

		List<RoomMember> roomMembers = new ArrayList<>();

		BookDto bookInfo = params.getBookInfo();
		Book book = bookRepository.findById(bookInfo.getBookId()).orElseThrow(
			() -> new EntityNotFoundException("해당하는 책 정보를 찾을 수 없습니다.")
		);

		RoomDto roomInfo = params.getRoomInfo();
		Room room = Room.builder()
			.book(book)
			.roomMembers(roomMembers)
			.hostId(roomInfo.getHostId())
			.title(roomInfo.getTitle())
			.password(roomInfo.getPassword())
			.isRecording(roomInfo.getIsRecording())
			.joinCnt(roomInfo.getJoinCnt())
			.limitCnt(book.getRoleCnt())
			.isPublic(roomInfo.getIsPublic())
			.sessionId(session.getSessionId())
			.build();

		// 세션과 커넥션을 생성합니다.
		Connection connection = session.createConnection(
			ConnectionProperties.fromJson(params.getConnectionProperties()).build());
		if (connection == null)
			throw new RuntimeException("토큰 생성 중 문제 발생");

		// 방 id와 token 데이터를 반환합니다.
		Map<String, String> resultData = new HashMap<>();
		resultData.put("roomId", String.valueOf(roomRepository.save(room).getRoomId()));
		resultData.put("token", connection.getToken());

		return resultData;
	}

	@Override
	public Session findSessionByRoomId(OpenVidu openvidu, Long roomId) {
		// 방 id 에 해당하는 방을 가져옵니다.
		Room room = roomRepository.findById(roomId).orElseThrow(
			() -> new EntityNotFoundException("해당하는 방을 찾을 수 없습니다.")
		);
		return openvidu.getActiveSession(room.getSessionId());
	}

	public List<Room> getAllRooms() {
		return roomRepository.findAllByOrderByIsRecordingAscCreatedAtDesc().orElseThrow(
			() -> new EntityNotFoundException("방 없음")
		);
	}

	@Override
	public String createConnection(OpenVidu openvidu, Session session,
		Map<String, Object> connectionProperties) throws OpenViduJavaClientException, OpenViduHttpException {
		// 방 참여자는 세션과 커넥션을 생성합니다.
		Connection connection = session.createConnection(
			ConnectionProperties.fromJson(connectionProperties).build());
		if (connection == null)
			throw new RuntimeException("토큰 생성 중 문제 발생");
		// 토큰을 반환합니다.
		return connection.getToken();
	}

	@Override
	public void checkJoinPossible(OpenVidu openvidu, Long roomId) {
		// 방 id 에 해당하는 방을 가져옵니다.
		Room room = roomRepository.findById(roomId).orElseThrow(
			() -> new EntityNotFoundException("해당하는 방을 찾을 수 없습니다.")
		);

		// // 방에 연결된 유효한 connection 리스트를 openvidu 서버에서 불러옵니다.
		// List<Connection> activeConnections = openvidu.getActiveSession(room.getSessionId()).getActiveConnections();
		// return activeConnections.size() < room.getLimitCnt();

		// db와 openvidu 서버 둘 다 확인하는 게 맞지만, 일단 해피케이스
		if (room.getJoinCnt() >= room.getLimitCnt()){
			throw new RuntimeException("인원 초과로 참여 불가");
		};
	}

	@Override
	public void addMemberToRoom(Long roomId, Long memberId) {
		// 방 id에 해당하는 방을 가져옵니다.
		Room room = roomRepository.findById(roomId).orElseThrow(
			() -> new EntityNotFoundException("해당하는 방을 찾을 수 없습니다.")
		);

		// member id에 해당하는 멤버를 방 참여 멤버로 등록합니다.
		Member member = memberRepository.findById(memberId).get();
		RoomMember roomMember = RoomMember.builder()
			.member(member)
			.room(room)
			.build();
		roomMemberRepository.save(roomMember);

		// 방 참여 인원을 갱신합니다.
		room.setJoinCnt(room.getJoinCnt() + 1);
		roomRepository.save(room);
	}

	@Override
	public void removeMemberFromRoom(OpenVidu openvidu, Long roomId, Long memberId) {
		// 방 참여 멤버를 DB에서 지웁니다.
		RoomMember roomMember = roomMemberRepository.findByRoomRoomIdAndMemberMemberId(roomId,
			memberId).orElseThrow(
			() -> new EntityNotFoundException("해당하는 방 참여자를 찾을 수 없습니다.")
		);

		roomMemberRepository.delete(roomMember);

		// 방 id 에 해당하는 방을 가져옵니다.
		Room room = roomRepository.findById(roomId).orElseThrow(
			() -> new EntityNotFoundException("해당하는 방을 찾을 수 없습니다.")
		);

		// 방 참여 인원을 갱신합니다.
		room.setJoinCnt(room.getJoinCnt() - 1);

		// 방에 더이상 남아있는 인원이 없다면 방을 삭제합니다.
		if (room.getJoinCnt() == 0) {
			roomRepository.delete(room);
		}
	}

	@Override
	public void updateRoom(Long roomId, RoomDto roomInfo) {
		Room room = roomRepository.findById(roomId).orElseThrow(
			() -> new EntityNotFoundException("해당하는 방이 존재하지 않습니다.")
		);

		// Room 엔티티의 roomMembers 필드를 복사하여 새로운 리스트 생성
		List<RoomMember> newRoomMembers = new ArrayList<>(room.getRoomMembers());

		// 새로운 Room 엔티티 생성
		Room newRoom = Room.builder()
			.book(room.getBook())
			.roomMembers(newRoomMembers)
			.hostId(roomInfo.getHostId())
			.title(roomInfo.getTitle())
			.password(roomInfo.getPassword())
			.isRecording(roomInfo.getIsRecording())
			.joinCnt(roomInfo.getJoinCnt())
			.limitCnt(room.getLimitCnt())
			.isPublic(roomInfo.getIsPublic())
			.sessionId(room.getSessionId())
			.build();

		roomRepository.save(newRoom);
	}

	@Override
	public Room getRoom(Long roomId) {
		return roomRepository.findById(roomId).orElseThrow(
			() -> new EntityNotFoundException(("해당하는 방이 존재하지 않습니다."))
		);
	}

	@Override
	public void removeExpiredRooms(List<Session> activeSessions) {
		List<String> activeSessionIdList = activeSessions.stream()
			.map(Session::getSessionId)
			.collect(Collectors.toList());
		roomRepository.deleteAllBySessionIdNotIn(activeSessionIdList);
	}

}