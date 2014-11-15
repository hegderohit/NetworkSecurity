package com.netsec.utd;

import javax.crypto.Cipher;

public class Encryption {

	public byte[] encrypt(String message) throws Exception {
		if (message == null) {
			return null;
		}
		// Get a cipher object.
		Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, MainClass.key);

		// Gets the raw bytes to encrypt, UTF8 is needed for
		// having a standard character set
		byte[] stringBytes = message.getBytes("UTF8");

		// encrypt using the cipher
		byte[] raw = cipher.doFinal(stringBytes);

		return raw;
	}
}
