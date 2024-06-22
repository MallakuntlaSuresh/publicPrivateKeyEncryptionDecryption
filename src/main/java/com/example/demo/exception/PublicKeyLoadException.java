package com.example.demo.exception;
public class PublicKeyLoadException extends Exception {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public PublicKeyLoadException(String message) {
        super(message);
    }

    public PublicKeyLoadException(String message, Throwable cause) {
        super(message, cause);
    }
}
