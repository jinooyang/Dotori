package com.dotori.backend.domain.room.service;

import java.util.List;
import java.util.Map;

import com.dotori.backend.domain.room.model.dto.RoomDto;
import com.dotori.backend.domain.room.model.dto.RoomInitializationDto;
import com.dotori.backend.domain.room.model.entity.Room;

import io.openvidu.java.client.OpenVidu;
import io.openvidu.java.client.OpenViduHttpException;
import io.openvidu.java.client.OpenViduJavaClientException;
import io.openvidu.java.client.Session;

public interface RoomService {

	Map<String, String> createRoom(OpenVidu openvidu, RoomInitializationDto params) throws Exception;

	Session findSessionByRoomId(OpenVidu openvidu, Long roomId) throws Exception;

	List<Room> getAllRooms();

	String createConnection(OpenVidu openvidu, Session session,
		Map<String, Object> connectionProperties) throws
		OpenViduJavaClientException,
		OpenViduHttpException;

	void checkJoinPossible(OpenVidu openvidu, Long roomId) throws Exception;

	void addMemberToRoom(Long roomId, Long memberId);

	void removeMemberFromRoom(OpenVidu openvidu, Long roomId, Long memberId);

	void updateRoom(Long roomId, RoomDto roomInfo);

	Room getRoom(Long roomId);

	void removeExpiredRooms(List<Session> activeSessions);
}
