package com.dotori.backend.common;

import java.io.File;
import java.util.Arrays;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class FileUtil {
	public static void deleteDirectory(File file) {
		log.info("[deleteDirectory] called");
		if (file == null || !file.exists()) {
			log.info("폴더가 존재하지 않습니다.");
			return;
		} else if (file.delete()) {
			log.info("{}: 파일이 삭제되었습니다.", file);
			return;
		}
		Arrays.stream(file.listFiles())
			.forEach(FileUtil::deleteDirectory);
		file.delete();
		log.info("[deleteDirectory] completed");
	}
}
