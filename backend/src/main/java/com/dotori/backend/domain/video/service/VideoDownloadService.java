package com.dotori.backend.domain.video.service;

import java.io.File;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class VideoDownloadService {
	public File downloadVideo(String path) {
		log.info("[downloadVideo] called");
		log.info("path: {}", path);
		return new File(path);
	}
}
