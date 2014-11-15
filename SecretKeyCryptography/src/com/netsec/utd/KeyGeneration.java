package com.netsec.utd;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;

public class KeyGeneration {

	public void generateKey() throws NoSuchAlgorithmException {
		KeyGenerator generator;
		generator = KeyGenerator.getInstance("DES");
		generator.init(new SecureRandom());
		MainClass.key = generator.generateKey();
		System.out.println("Key Generated:\t" + MainClass.key.toString());
	}
}
