package com.netsec.utd;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class KeyGeneration {

	public SecretKey generateKey() throws NoSuchAlgorithmException {
		
		SecretKey key;
		key = KeyGenerator.getInstance("DES").generateKey();
		System.out.println("Key Generated:\t" + key.toString());
		return key;
	}
}
