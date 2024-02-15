package com.dotori.backend.common.config;

import java.io.File;
import java.io.IOException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

@Configuration
public class VideoPathConfig {
	@Value("file:${videos.path.video}")
	private Resource videoDirectory;
	@Value("file:${videos.path.scene}")
	private Resource sceneDirectory;
	@Value("file:${videos.path.chunk}")
	private Resource chunkDirectory;

	@Bean
	public File videoDirectory() throws IOException {
		File directory = videoDirectory.getFile();
		if (!directory.isDirectory() || !directory.exists()) {
			throw new IllegalArgumentException("video 경로가 잘못되었습니다.");
		}
		return directory;
	}

	@Bean
	public File sceneDirectory() throws IOException {
		File directory = sceneDirectory.getFile();
		if (!directory.isDirectory() || !directory.exists()) {
			throw new IllegalArgumentException("scene 경로가 잘못되었습니다.");
		}
		return directory;
	}

	@Bean
	public File chunkDirectory() throws IOException {
		File directory = chunkDirectory.getFile();
		if (!directory.isDirectory() || !directory.exists()) {
			throw new IllegalArgumentException("chunk 경로가 잘못되었습니다.");
		}
		return directory;
	}
}
