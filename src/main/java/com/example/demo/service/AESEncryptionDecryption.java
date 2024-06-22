package com.example.demo.service;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.example.demo.exception.DecryptionException;
import com.example.demo.exception.EncryptionException;
import com.example.demo.exception.PrivateKeyLoadException;
import com.example.demo.exception.PublicKeyLoadException;

public class AESEncryptionDecryption {
	private static Logger logger = LoggerFactory.getLogger(AESEncryptionDecryption.class);

	private AESEncryptionDecryption() {
	}

	private static final String AES_ALGORITHM = "AES";
	private static final String RSA_ALGORITHM = "RSA";
	private static PublicKey publicKey = null;
	private static PrivateKey privateKey = null;
	private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
	private static final int GCM_TAG_LENGTH = 16;
	private static final int GCM_IV_LENGTH = 12;
	private static final String PUBLIC_KEY_FILE = "publicKey.txt";
	private static final String PRIVATE_KEY_FILE = "privateKey.txt";

	// Method to generate and save RSA key pair to files
	public static void generateAndSaveKeys() {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
			keyGen.initialize(2048);
			KeyPair keyPair = keyGen.generateKeyPair();
			saveKeyToFile(PUBLIC_KEY_FILE, keyPair.getPublic().getEncoded());
			saveKeyToFile(PRIVATE_KEY_FILE, keyPair.getPrivate().getEncoded());

		} catch (Exception e) {
			logger.info("Exception Occured :: {}", e.getMessage());
		}
	}

	static {
		try {
			publicKey = loadPublicKey(PUBLIC_KEY_FILE);
			privateKey = loadPrivateKey(PRIVATE_KEY_FILE);
		} catch (Exception e) {
			logger.info("Exception Occured :: {}", e.getMessage());
		}
	}

	public static String generateKey() throws NoSuchAlgorithmException {
		SecureRandom secureRandom = new SecureRandom();
		KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
		keyGen.init(256, secureRandom);
		SecretKey secretKey = keyGen.generateKey();
		byte[] keyBytes = secretKey.getEncoded();
		return DatatypeConverter.printBase64Binary(keyBytes);
	}

	public static String encrypt(String data, String base64Key) throws EncryptionException {
		try {
			byte[] keyBytes = DatatypeConverter.parseBase64Binary(base64Key);
			SecretKeySpec keySpec = new SecretKeySpec(keyBytes, AES_ALGORITHM);
			byte[] iv = new byte[GCM_IV_LENGTH];
			SecureRandom secureRandom = new SecureRandom();
			secureRandom.nextBytes(iv);
			Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
			GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

			byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

			byte[] ivAndEncryptedData = new byte[GCM_IV_LENGTH + encryptedData.length];
			System.arraycopy(iv, 0, ivAndEncryptedData, 0, GCM_IV_LENGTH);
			System.arraycopy(encryptedData, 0, ivAndEncryptedData, GCM_IV_LENGTH, encryptedData.length);

			return Base64.getEncoder().encodeToString(ivAndEncryptedData);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException | InvalidAlgorithmParameterException | IllegalArgumentException
				| NullPointerException e) {
			throw new EncryptionException("Error encrypting data: " + e.getMessage(), e);
		}
	}

	public static String getHashValue(String data) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
		StringBuilder hexString = new StringBuilder();

		for (byte b : hash) {
			String hex = String.format("%02x", b & 0xff);
			hexString.append(hex);
		}

		return hexString.toString();
	}

	public static String decrypt(String encryptedData, String base64Key) throws DecryptionException {
		try {
			byte[] keyBytes = DatatypeConverter.parseBase64Binary(base64Key);
			byte[] ivAndEncryptedData = Base64.getDecoder().decode(encryptedData);

			byte[] iv = new byte[GCM_IV_LENGTH];
			System.arraycopy(ivAndEncryptedData, 0, iv, 0, GCM_IV_LENGTH);
			byte[] encryptedBytes = new byte[ivAndEncryptedData.length - GCM_IV_LENGTH];
			System.arraycopy(ivAndEncryptedData, GCM_IV_LENGTH, encryptedBytes, 0, encryptedBytes.length);

			SecretKeySpec keySpec = new SecretKeySpec(keyBytes, AES_ALGORITHM);
			Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
			GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);
			cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

			byte[] decryptedData = cipher.doFinal(encryptedBytes);

			return new String(decryptedData, StandardCharsets.UTF_8);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
				| IllegalArgumentException | NullPointerException e) {
			throw new DecryptionException("Error decrypting data: " + e.getMessage(), e);
		}
	}

	public static byte[] encrypt(String message, PublicKey publicKey) throws EncryptionException {
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			return cipher.doFinal(message.getBytes("UTF-8"));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException | UnsupportedEncodingException e) {
			throw new EncryptionException("Error encrypting data: " + e.getMessage(), e);
		}
	}

	public static String getEncStringWithPublicKey(String originalMessage)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, EncryptionException {
		byte[] encryptedBytes = encrypt(originalMessage, publicKey);
		return Base64.getEncoder().encodeToString(encryptedBytes);
	}

	public static String decrypt(byte[] encryptedBytes, PrivateKey privateKey) throws DecryptionException {
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
			return new String(decryptedBytes, "UTF-8");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException | UnsupportedEncodingException e) {
			throw new DecryptionException("Error decrypting data: " + e.getMessage(), e);
		}
	}

	public static String getDecStringWithPrivateKey(String encString)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, DecryptionException {
		byte[] decodedBytes = Base64.getDecoder().decode(encString);
		return decrypt(decodedBytes, privateKey);
	}

	public static void saveKeyToFile(String filePath, byte[] keyBytes) throws IOException {
		try (FileOutputStream fos = new FileOutputStream(filePath)) {
			fos.write(Base64.getEncoder().encode(keyBytes));
		}
	}

	public static PublicKey loadPublicKey(String filePath) throws PublicKeyLoadException {
		try {
			byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));
			byte[] decodedKey = Base64.getDecoder().decode(keyBytes);

			KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
			return keyFactory.generatePublic(keySpec);

		} catch (Exception e) {
			throw new PublicKeyLoadException("Failed to load public key from file: " + filePath, e);
		}
	}

	public static PrivateKey loadPrivateKey(String filePath) throws PrivateKeyLoadException {
		try {
			byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));
			byte[] decodedKey = Base64.getDecoder().decode(keyBytes);

			KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
			return keyFactory.generatePrivate(keySpec);

		} catch (Exception e) {
			throw new PrivateKeyLoadException("Failed to load private key from file: " + filePath, e);
		}
	}

}