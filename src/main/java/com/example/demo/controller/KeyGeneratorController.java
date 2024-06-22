package com.example.demo.controller;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.exception.DecryptionException;
import com.example.demo.exception.EncryptionException;
import com.example.demo.service.AESEncryptionDecryption;

@RestController
public class KeyGeneratorController {
	private static Logger logger = LoggerFactory.getLogger(KeyGeneratorController.class);

	private static final String PAYLOAD = "payload";

	@PostMapping("/ecncryptedkey")
	public ResponseEntity<String> aesEncryptKey(@RequestBody String json)
			throws NoSuchAlgorithmException, EncryptionException, InvalidKeyException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException {
		JSONObject jsonObject = new JSONObject();
		String aesKey = AESEncryptionDecryption.generateKey();
		setHoldEncKey(aesKey);
		String encyptjsonReq = AESEncryptionDecryption.encrypt(json, aesKey);
		String encryptedAesKey = AESEncryptionDecryption.getEncStringWithPublicKey(aesKey);
		String hashValue = AESEncryptionDecryption.getHashValue(encyptjsonReq);
		jsonObject.put("encryptedAesKey", encryptedAesKey);
		jsonObject.put(PAYLOAD, encyptjsonReq);
		jsonObject.put("hashValue", hashValue);
		return ResponseEntity.status(HttpStatus.OK).contentType(MediaType.APPLICATION_JSON).body(jsonObject.toString());
	}

	private String holdEncKey;

	public String getHoldEncKey() {
		return holdEncKey;
	}

	public void setHoldEncKey(String holdEncKey) {
		this.holdEncKey = holdEncKey;
	}

	@PostMapping("/decrpytkey")
	public ResponseEntity<String> aesDecrpytKey(@RequestBody String json) throws DecryptionException {
		JSONObject jsonObject = new JSONObject(json);
		String decryptReqest = AESEncryptionDecryption.decrypt(jsonObject.getString(PAYLOAD), getHoldEncKey()); // Get
		return ResponseEntity.status(HttpStatus.OK).contentType(MediaType.APPLICATION_JSON).body(decryptReqest);
	}

	@PostMapping("/verify")
	public void name(@RequestHeader String key, @RequestBody Map<String, String> payload)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, DecryptionException {
		logger.info("payload is ::{} ", payload);
		logger.info("key is :: {}", key);
		String decStringWithPrivateKey = AESEncryptionDecryption.getDecStringWithPrivateKey(key);
		String decrypt = AESEncryptionDecryption.decrypt(payload.get(PAYLOAD), decStringWithPrivateKey);
		logger.info(decrypt);
	}
}
