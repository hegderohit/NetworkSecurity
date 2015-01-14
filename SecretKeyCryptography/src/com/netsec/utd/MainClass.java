package com.netsec.utd;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

public class MainClass {
	// Global CatalogList
	static List<Product> catalogList = new ArrayList<Product>();
	static SecretKey key1, key2, key3;

	public static void main(String[] args) throws Exception {

		// Intialization Phase
		intializationMethod();
		SealedEncryption sEncryption = new SealedEncryption();
		SealedDecrytpion sDecrytpion = new SealedDecrytpion();

		/*
		 * k1 - user and service k2 - broker and user k3 - service and broker
		 * STEP1: k2(k1(data)) to broker
		 */

		Message msg = new Message();
		Message message = msg.AuthenticationMessage("100", "Mac", "Mac102");

		SealedObject cipherText = sEncryption.encryptMessage(message, key1);

		System.out.println(cipherText.toString());

		Message plainMessage = (Message) sDecrytpion.decryptMessage(cipherText,
				key1);
		System.out.println("Original Object: " + plainMessage);

	}

	private static void intializationMethod() {
		// TODO Auto-generated method stub
		createAndAddProducts();
		keyGeneration();
	}

	private static void keyGeneration() {
		// Method to generate Session Keys
		KeyGeneration keyGeneration = new KeyGeneration();
		try {
			key1 = keyGeneration.generateKey();
			key2 = keyGeneration.generateKey();
			key3 = keyGeneration.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

	}

	private static void createAndAddProducts() {
		// Method to create and add products
		Product productx = new Product("ProductX", "20", "Clothing");
		Product producty = new Product("ProductY", "200", "Electronics");
		Product productz = new Product("ProductZ", "150", "Education");
		Product producta = new Product("ProductA", "24", "Clothing");
		Product productb = new Product("ProductB", "35", "Electronics");

		catalogList.add(producta);
		catalogList.add(productb);
		catalogList.add(productx);
		catalogList.add(producty);
		catalogList.add(productz);

	}

	// [TODO]: Add this to appropriate node

	// At Client Side
	public void processBrokerMessage(SealedObject sealed)
			throws InvalidKeyException, IllegalBlockSizeException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			ClassNotFoundException, BadPaddingException, IOException {

		SealedEncryption sEncryption = new SealedEncryption();
		SealedDecrytpion sDecrytpion = new SealedDecrytpion();

		// Decrypt the message
		Message msg = (Message) sDecrytpion.decryptMessage(sealed, key1);
		String msgType = msg.Message_Type;

		if (msgType.equalsIgnoreCase("AuthenticationMessage")) {
			/*
			 * Read Nonce If Valid then send catalog req message
			 */
		} else if (msgType.equalsIgnoreCase("BrokerCatalogReplyMessage")) {
			/*
			 * Read the catalog send purchase mesage with k3 encryption
			 */

		} else if (msgType.equalsIgnoreCase("ServerPurchaseConfirmMessage")) {
			// MSG= ServerPurchaseConfirmMessage,200
		}

	}

	// Broker Side for CLient
	public void processClientMessage(SealedObject sealed)
			throws InvalidKeyException, IllegalBlockSizeException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			ClassNotFoundException, BadPaddingException, IOException {

		SealedEncryption sEncryption = new SealedEncryption();
		SealedDecrytpion sDecrytpion = new SealedDecrytpion();

		// Decrypt the message
		Message msg = (Message) sDecrytpion.decryptMessage(sealed, key1);
		String msgType = msg.Message_Type;

		if (msgType.equalsIgnoreCase("AuthenticationMessage")) {
			/*
			 * Read Nonce If Valid then send Nonce back to client
			 */
		} else if (msgType.equalsIgnoreCase("ClientCatalogRequest")) {
			/*
			 * Get the Server Name Send the Request to that server
			 */
		}else if(msgType.equalsIgnoreCase("ClientPurchaseMessage")){
			/*
			 * Decrypt with k1 and encrypt with k2 fwd to Server
			 * 
			 */
		}

	}
	
	//Broker Side for Server
	public void processServerMessage(SealedObject sealed)
			throws InvalidKeyException, IllegalBlockSizeException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			ClassNotFoundException, BadPaddingException, IOException {

		SealedEncryption sEncryption = new SealedEncryption();
		SealedDecrytpion sDecrytpion = new SealedDecrytpion();

		// Decrypt the message
		Message msg = (Message) sDecrytpion.decryptMessage(sealed, key1);
		String msgType = msg.Message_Type;

		if (msgType.equalsIgnoreCase("AuthenticationMessage")) {
			/*
			 * Read Nonce If Valid
			 * Send CatalogRequest 
			 */
		} else if (msgType.equalsIgnoreCase("ServerCatalogReplyMessage")) {
			/*
			 * Send back the message decryprty and encryprt
			 */
		}
		 else if (msgType.equalsIgnoreCase("ServerPurchaseConfirmMessage")) {
				/*
				 * Decrypt and encrypt back with k1 and fwd it to client
				 */
			}

	}
	
	// Server Side
	public void processBrokerMessageServerSide(SealedObject sealed)
			throws InvalidKeyException, IllegalBlockSizeException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			ClassNotFoundException, BadPaddingException, IOException {

		SealedEncryption sEncryption = new SealedEncryption();
		SealedDecrytpion sDecrytpion = new SealedDecrytpion();

		// Decrypt the message
		Message msg = (Message) sDecrytpion.decryptMessage(sealed, key1);
		String msgType = msg.Message_Type;

		if (msgType.equalsIgnoreCase("AuthenticationMessage")) {
			/*
			 * Read Nonce If Valid
			 * Reply back to Broker
			 */
		} else if (msgType.equalsIgnoreCase("BrokerCatalogRequest")) {
			/*
			 * Decrypt and encrypt back with k3 and k2 send to broker
			 */
		}
		 else if (msgType.equalsIgnoreCase("ClientPurchaseMessage")) {
				/*
				 * send confirm message
				 */
			}

	}
	
	
	
}
