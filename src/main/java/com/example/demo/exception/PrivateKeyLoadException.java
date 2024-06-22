package com.example.demo.exception;

public class PrivateKeyLoadException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public PrivateKeyLoadException(String message) {
		super(message);
	}

	public PrivateKeyLoadException(String message, Throwable cause) {
		super(message, cause);
	}
}
