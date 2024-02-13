package com.dotori.backend.domain.video.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.dotori.backend.domain.room.model.entity.Room;
import com.dotori.backend.domain.video.model.entity.SceneVideo;

public interface SceneVideoRepository extends JpaRepository<SceneVideo, Long> {
	List<SceneVideo> findALlByRoom(Room room);

	Optional<SceneVideo> getSceneVideoByRoomAndSceneOrder(Room room, int sceneOrder);
}
