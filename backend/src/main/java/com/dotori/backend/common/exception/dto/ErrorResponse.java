package com.dotori.backend.common.exception.dto;

import static java.util.Collections.*;
import static java.util.stream.Collectors.*;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.validation.FieldError;

import com.fasterxml.jackson.annotation.JsonFormat;

import lombok.Getter;

@Getter
public class ErrorResponse {
	private final String message;
	private final String path;
	@JsonFormat(pattern = "yyyy-MM-ss")
	private final LocalDateTime time;
	private final List<FieldErrorMessage> fieldErrorMessages;

	private ErrorResponse(
		String message, String path, LocalDateTime time, List<FieldError> fieldErrors
	) {
		this.message = message;
		this.path = path;
		this.time = time;
		this.fieldErrorMessages = fieldErrors.stream()
			.map(FieldErrorMessage::new)
			.collect(toList());
	}

	public static ErrorResponse of(String message, String path) {
		return new ErrorResponse(message, path, LocalDateTime.now(), emptyList());
	}

	public static ErrorResponse of(
		String message, String path, List<FieldError> inputErrors
	) {
		return new ErrorResponse(message, path, LocalDateTime.now(), inputErrors);
	}

}
