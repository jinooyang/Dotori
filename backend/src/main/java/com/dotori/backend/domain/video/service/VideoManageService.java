package com.dotori.backend.domain.video.service;

import static com.dotori.backend.domain.video.model.VideoMapper.*;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.persistence.EntityNotFoundException;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.dotori.backend.domain.member.model.entity.Member;
import com.dotori.backend.domain.member.model.entity.MemberVideo;
import com.dotori.backend.domain.room.model.entity.Room;
import com.dotori.backend.domain.video.model.dto.VideoDto;
import com.dotori.backend.domain.video.model.entity.SceneVideo;
import com.dotori.backend.domain.video.model.entity.Video;
import com.dotori.backend.domain.video.repository.MemberVideoRepository;
import com.dotori.backend.domain.video.repository.SceneVideoRepository;
import com.dotori.backend.domain.video.repository.VideoRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class VideoManageService {
	private final VideoRepository videoRepository;
	private final SceneVideoRepository sceneVideoRepository;
	private final MemberVideoRepository memberVideoRepository;

	@Transactional
	public VideoDto saveVideo(String path) {
		return toVideoDto(videoRepository.save(
			Video.builder()
				.path(path)
				.build()
		));
	}

	@Transactional
	public VideoDto getVideo(Long videoId) {
		Video video = videoRepository.findById(videoId)
			.orElseThrow(() -> new EntityNotFoundException("해당하는 비디오가 존재하지 않습니다."));
		return toVideoDto(video);
	}

	@Transactional
	public SceneVideo saveSceneVideo(Room room, int sceneOrder, String savedPath) {
		return sceneVideoRepository.save(
			SceneVideo.builder()
				.room(room)
				.sceneOrder(sceneOrder)
				.path(savedPath)
				.build()
		);
	}

	@Transactional(readOnly = true)
	public Optional<SceneVideo> getSceneVideByRoomAndSceneOrder(Room room, int sceneOrder) {
		return sceneVideoRepository.getSceneVideoByRoomAndSceneOrder(room, sceneOrder);
	}

	@Transactional
	public List<SceneVideo> getSceneVideoByRoom(Room room) {
		return sceneVideoRepository.findALlByRoom(room);
	}

	@Transactional
	public void deleteSceneVideos(List<SceneVideo> sceneVideos) {
		sceneVideoRepository.deleteAllInBatch(sceneVideos);
	}

	@Transactional
	public void saveMemberVideos(List<Member> members, Video video, Long bookId) {
		List<MemberVideo> memberVideos = members.stream()
			.map(member -> MemberVideo
				.builder()
				.member(member)
				.video(video)
				.bookId(bookId)
				.build()
			).collect(Collectors.toList());

		memberVideoRepository.saveAll(memberVideos);
	}
}