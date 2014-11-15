package com.netsec.utd;

import java.security.Key;

public class MainClass {
	static Key key;

	public static void main(String[] args) throws Exception {
		// Class Object to generate the Session Key
		KeyGeneration keyGeneration = new KeyGeneration();
		// Encryption Object
		Encryption encryption = new Encryption();
		// Decryption Class
		Decryption decryption = new Decryption();

		keyGeneration.generateKey();
		String message = "This is Test Message";
		System.out.println("Plain Text:\t " + message);

		byte[] cipherText = encryption.encrypt(message);
		System.out.println("Cipher Text is:\t" + cipherText);

		String recoveredText = decryption.decrypt(cipherText);
		System.out.println("Recovered Text is:\t" + recoveredText);
	}
}
