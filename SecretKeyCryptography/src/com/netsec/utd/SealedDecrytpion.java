package com.netsec.utd;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

public class SealedDecrytpion {
	private static Cipher dcipher;

	public Message decryptMessage(SealedObject sealed, SecretKey key)
			throws InvalidKeyException, IllegalBlockSizeException, IOException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			ClassNotFoundException, BadPaddingException {
		dcipher = Cipher.getInstance("DES");
		 dcipher.init(Cipher.DECRYPT_MODE, key);

		Message message = (Message) sealed.getObject(dcipher);
		return message;
	}

}
