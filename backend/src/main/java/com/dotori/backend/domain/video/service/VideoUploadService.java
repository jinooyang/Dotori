package com.dotori.backend.domain.video.service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.dotori.backend.common.FileUtil;
import com.dotori.backend.domain.video.model.dto.VideoSceneUploadRequest;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class VideoUploadService {
	private final File chunkDirectory;
	private final File sceneDirectory;
	public static final String TEMP_PART_NAME = "temp.part";

	public File uploadChunkFiles(VideoSceneUploadRequest videoSceneUploadRequest) {
		log.info("[uploadChunkFiles] called");

		File tempDirectory = uploadChunkFile(
			videoSceneUploadRequest.getFileName(),
			videoSceneUploadRequest.getChunkFile(),
			videoSceneUploadRequest.getChunkNumber()
		);

		File uploadedFile;
		if (videoSceneUploadRequest.isEnd()) {
			String[] fileName = splitFileName(videoSceneUploadRequest.getFileName());
			uploadedFile = mergeChunkFiles(fileName[0], tempDirectory, fileName[1]);
			deleteChunkFiles(tempDirectory);
			return uploadedFile;
		}
		return null;
	}

	private File uploadChunkFile(String fileName, MultipartFile chunkFile, int chunkNumber) {
		log.info("[uploadChunkFile] called");
		Path savedDirectory = chunkDirectory.toPath().resolve(fileName);
		String chunkFileName = TEMP_PART_NAME + chunkNumber;

		try {
			if (savedDirectory.toFile().mkdirs()) {
				log.info("{} directory is created", savedDirectory);
			}
			Files.write(savedDirectory.resolve(chunkFileName), chunkFile.getBytes());
		} catch (RuntimeException e) {
			log.info("chunk file upload failed", e);
			throw e;
		} catch (IOException e) {
			log.info("chunk file upload failed", e);
			throw new RuntimeException(e.getMessage());
		}
		return savedDirectory.toFile();
	}

	private String[] splitFileName(String originalFileName) {
		int idx = originalFileName.lastIndexOf(".");
		String[] result = {originalFileName, ".mkv"};
		if (idx > 0) {
			result[0] = originalFileName.substring(0, idx);
			result[1] = originalFileName.substring(idx);
		}
		return result;
	}

	private File mergeChunkFiles(String fileName, File tempDirectory, String fileExtension) {
		log.info("[mergeChunkFiles] called");
		File output;
		try {
			output = sceneDirectory.toPath()
				.resolve(fileName + fileExtension)
				.toFile();

			if (output.exists()) {
				output.delete();
			}
			output.createNewFile();

			for (int i = 0; i < tempDirectory.listFiles().length; i++) {
				Files.write(
					output.toPath(),
					Files.readAllBytes(tempDirectory.toPath().resolve(TEMP_PART_NAME + i)),
					StandardOpenOption.APPEND
				);
			}
		} catch (IOException e) {
			log.info("[mergeChunkFiles] failed");
			log.info("exception thrown: ", e);
			throw new RuntimeException(e);
		}
		log.info("[mergeChunkFiles] completed scene video is merged");
		return output;
	}

	private void deleteChunkFiles(File file) {
		FileUtil.deleteDirectory(file);
	}
}