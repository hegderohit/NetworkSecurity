package com.netsec.utd;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

public class SealedEncryption {
	private static Cipher ecipher;

	public SealedObject encryptMessage(Message message, SecretKey key)
			throws InvalidKeyException, IllegalBlockSizeException, IOException,
			NoSuchAlgorithmException, NoSuchPaddingException{
		ecipher = Cipher.getInstance("DES");
		ecipher.init(Cipher.ENCRYPT_MODE, key);
		
		SealedObject sealed = new SealedObject(message, ecipher);
		return sealed;
	}
	
}
