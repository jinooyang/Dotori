package com.dotori.backend.common.exception.dto;

import javax.validation.constraints.NotNull;

import org.springframework.lang.Nullable;
import org.springframework.validation.FieldError;

import lombok.Getter;

@Getter
public class FieldErrorMessage {
	private final String objectName;
	private final String field;
	private final String message;
	@Nullable
	private final Object rejectedValue;
	private final String code;

	public FieldErrorMessage(
		String objectName, String field, String message, @Nullable Object rejectedValue, String code
	) {
		this.objectName = objectName;
		this.field = field;
		this.message = message;
		this.rejectedValue = rejectedValue;
		this.code = code;
	}

	public FieldErrorMessage(@NotNull FieldError fieldError) {
		this(fieldError.getObjectName(), fieldError.getField(), fieldError.getDefaultMessage(),
			fieldError.getRejectedValue(), fieldError.getCode()
		);
	}

	@Override
	public String toString() {
		return String.format(
			"FieldErrorMessage{"
				+ "objectName='%s', "
				+ "field='%s', "
				+ "message='%s', "
				+ "rejectedValue=%s, "
				+ "code='%s'"
				+ "}",
			objectName, field, message, rejectedValue, code
		);
	}
}
