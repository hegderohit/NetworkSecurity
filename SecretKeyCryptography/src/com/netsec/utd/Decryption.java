package com.netsec.utd;

import javax.crypto.Cipher;

public class Decryption {
	public String decrypt(byte[] encrypted) throws Exception {

		// Get a cipher object.
		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, MainClass.key);

		// decode the message
		byte[] stringBytes = cipher.doFinal(encrypted);

		// converts the decoded message to a String
		String clear = new String(stringBytes, "UTF8");
		return clear;
	}
}
