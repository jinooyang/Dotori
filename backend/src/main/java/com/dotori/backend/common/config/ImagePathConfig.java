package com.dotori.backend.common.config;

import java.io.File;
import java.io.IOException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

@Configuration
public class ImagePathConfig {
	@Value("file:${images.path.profile.save}")
	private Resource profileImageSaveDirectory;


	@Bean
	public File profileImageSaveDirectory() throws IOException {
		File directory = profileImageSaveDirectory.getFile();
		if (!directory.isDirectory() || !directory.exists()) {
			throw new IllegalArgumentException("Profile Image 경로가 잘못되었습니다.");
		}
		return directory;
	}
}
