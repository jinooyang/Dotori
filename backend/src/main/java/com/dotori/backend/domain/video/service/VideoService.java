package com.dotori.backend.domain.video.service;

import static com.dotori.backend.domain.video.model.VideoMapper.*;

import java.io.File;
import java.util.List;
import java.util.stream.Collectors;

import javax.persistence.EntityNotFoundException;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.dotori.backend.domain.member.model.entity.Member;
import com.dotori.backend.domain.room.model.entity.Room;
import com.dotori.backend.domain.room.model.entity.RoomMember;
import com.dotori.backend.domain.room.repository.RoomRepository;
import com.dotori.backend.domain.video.model.dto.VideoDto;
import com.dotori.backend.domain.video.model.dto.VideoSceneUploadRequest;
import com.dotori.backend.domain.video.model.dto.request.SceneVideoSaveRequest;
import com.dotori.backend.domain.video.model.dto.request.VideoMergeRequest;
import com.dotori.backend.domain.video.model.entity.SceneVideo;
import com.dotori.backend.domain.video.model.entity.Video;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class VideoService {
	private final VideoUploadService videoUploadService;
	private final VideoDownloadService videoDownloadService;
	private final VideoMergeService videoMergeService;
	private final VideoManageService videoManageService;

	private final RoomRepository roomRepository;

	@Transactional
	public boolean uploadSceneVideo(VideoSceneUploadRequest videoSceneUploadRequest) {
		File uploadSceneVideo = videoUploadService.uploadChunkFiles(videoSceneUploadRequest);
		if (uploadSceneVideo == null) {
			return false;
		}

		Room room = roomRepository.findById(videoSceneUploadRequest.getRoomId())
			.orElseThrow(EntityNotFoundException::new);

		videoManageService.saveSceneVideo(room, videoSceneUploadRequest.getSceneOrder(), uploadSceneVideo.toString());
		return true;
	}

	@Transactional(readOnly = true)
	public File downloadVideo(Long videoId) {
		log.info("[downloadVideo] called");
		VideoDto videoDto = videoManageService.getVideo(videoId);
		return videoDownloadService.downloadVideo(videoDto.getPath());
	}

	@Transactional
	public void saveSceneVideo(SceneVideoSaveRequest sceneVideoSaveRequest) {
		log.info("[saveSceneVideo] called");
		Room room = roomRepository.findById(sceneVideoSaveRequest.getRoomId())
			.orElseThrow(EntityNotFoundException::new);

		videoManageService.saveSceneVideo(
			room,
			sceneVideoSaveRequest.getSceneOrder(),
			sceneVideoSaveRequest.getSavedPath()
		);
	}

	@Transactional
	public void mergeSceneVideo(Long roomId) {
		log.info("[mergeSceneVideo] called");
		Room room = roomRepository.findById(roomId)
			.orElseThrow(EntityNotFoundException::new);

		List<SceneVideo> sceneVideos = videoManageService.getSceneVideoByRoom(room);
		List<String> paths = sceneVideos.stream()
			.map(SceneVideo::getPath)
			.collect(Collectors.toList());

		String savedPath = videoMergeService.videoMerge(new VideoMergeRequest(paths));
		VideoDto savedVideoDto = videoManageService.saveVideo(savedPath);
		saveMemberVideos(room.getRoomId(), savedVideoDto.getVideoId()); // TODO 비동기

		deleteSceneVideos(sceneVideos);
	}

	@Transactional
	public void deleteSceneVideos(List<SceneVideo> sceneVideos) {
		videoMergeService.deleteMergedFile();
		videoManageService.deleteSceneVideos(sceneVideos);
	}

	@Transactional
	public void saveMemberVideos(Long roomId, Long videoId) {
		log.info("[savedMemberVideos] called");
		Room room = roomRepository.findById(roomId)
			.orElseThrow(EntityNotFoundException::new);

		List<Member> members = room
			.getRoomMembers()
			.stream()
			.map(RoomMember::getMember)
			.collect(Collectors.toList());

		Video video = toVideo(videoManageService.getVideo(videoId));
		videoManageService.saveMemberVideos(members, video, room.getBook().getBookId());
	}
}