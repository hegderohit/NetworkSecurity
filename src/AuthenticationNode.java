import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Random;
import java.util.Scanner;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.core.FlexiCoreProvider;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

class MailerAuthenticationServer implements Runnable {

	public static synchronized void send(Message m) {
		try {
			AuthenticationNode.oos.writeObject(m);
			AuthenticationNode.oos.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	@Override
	public void run() {
		// TODO Auto-generated method stub

		while (true) {
			try {

				Message m = (Message) AuthenticationNode.ois.readObject();
				if (m != null) {
					System.out.println("\nReceived Message From:\t" + m.userName);
				}
				System.out.println("Hash table:"+AuthenticationNode.userList);
				
				//System.out.println("Hash table:"+AuthenticationNode.userList);
				SecretKey secKey = AuthenticationNode.loadKey(AuthenticationNode.userList
						.get(m.userName));
				System.out.println("Password Key:\t" + secKey);
				byte[] decryptedPasswordBuffer = AuthenticationNode.decryptMsg(
						m.passwordBuffer, secKey);
					
				if (m.msgType == 6) {
					
					System.out.println("\t\t\t\t\t**********Message 1**********");
					String cliPwd = new String(decryptedPasswordBuffer);
					System.out.println("Decripted pwd:\t" + cliPwd);
					String checkPwd = AuthenticationNode.userList.get(m.userName);

					System.out.println("Received Hash:\t"
							+ ByteUtils.toHexString(m.buffer));
					byte[] hashBuffer = AuthenticationNode.generateHash(
							m.userName.getBytes(),AuthenticationNode.loadKey("AccessKey"));
					System.out.println("Verified Hash:\t"+ ByteUtils.toHexString(hashBuffer));
					String s1 = ByteUtils.toHexString(hashBuffer);
					String s2 = ByteUtils.toHexString(m.buffer);

					if (!s1.trim().equals(s2.trim())) {
						System.out.println("Message Integrity compromised");
						MailerAuthenticationServer.send(m);
						continue;
					}

					System.out.println("Verify Password:" + checkPwd);
					if (checkPwd.equalsIgnoreCase(cliPwd.trim())) {
						System.out.println("Client Authenticated");

						int msgType = 7;
						String status = "OK";
						long validity=1;
						// GENERATE 3 SESSION KEYS
						if (status.trim().equals("OK")) {
							System.out.println("Authenticated by the Sever, Token Ready");
							System.out.println("Token Sent!!!");
						//long l = System.currentTimeMillis();
						//String temp = m.userName;
						byte[] token = AuthenticationNode.generateHash(m.userName.getBytes(),AuthenticationNode.loadKey("serverKey"));
						System.out.println("Generated token :\t" + token);
						
						SecretKey sessionKeyCLI_EMS = AuthenticationNode.dummyKeyGenerator();
						byte[] sessionKeyCLI_EMSBuffer = AuthenticationNode.toByteStream(sessionKeyCLI_EMS);
						System.out.println("Generated Session Key-1 :\t" + sessionKeyCLI_EMS);
						AuthenticationNode.sessionKeyTable1.put(m.userName, sessionKeyCLI_EMS);
						
						SecretKey sessionKeyEMS_FS = AuthenticationNode.dummyKeyGenerator();
						byte[] sessionKeyEMS_FSBuffer = AuthenticationNode.toByteStream(sessionKeyEMS_FS);
						System.out.println("Generated Session Key- 2 :\t" + sessionKeyEMS_FS);
						AuthenticationNode.sessionKeyTable2.put(m.userName, sessionKeyEMS_FS);
						
						SecretKey sessionKeyCLI_FS = AuthenticationNode.dummyKeyGenerator();
						byte[] sessionKeyCLI_FSBuffer = AuthenticationNode.toByteStream(sessionKeyCLI_FS);
						System.out.println("Generated Session Key- 3 :\t" + sessionKeyCLI_FS);
						AuthenticationNode.sessionKeyTable3.put(m.userName, sessionKeyCLI_FS);
						
						System.out.println("Session Keys Hash Table- 3 :\t" + AuthenticationNode.sessionKeyTable1);
						System.out.println( AuthenticationNode.sessionKeyTable2);
						System.out.println( AuthenticationNode.sessionKeyTable3);
						
						byte[] buffer = AuthenticationNode.generateHash(m.userName.getBytes(),AuthenticationNode.loadKey("AccessKey"));
						Message m1 = new Message(msgType, m.userName,
								AuthenticationNode.newpacker(status.getBytes()),validity,token,
								buffer, sessionKeyCLI_EMSBuffer,sessionKeyEMS_FSBuffer,sessionKeyCLI_FSBuffer,
								AuthenticationNode.random.nextLong());
						
						MailerAuthenticationServer.send(m1);
						
						System.out.println("\nEnter option");
						continue;
						}

					} else {
						System.out.println("Unauthenticated user");
					}
				}
				
				
			}catch (IOException e) {
				System.out.println(e.toString());
				e.printStackTrace();
				System.out.println("You are not an Authentic User!!!");
			} catch (ClassNotFoundException e) {
				System.out.println(e.toString());
			}

		}

	}

}

public class AuthenticationNode {

	static ServerSocket serverSocket;
	static BufferedReader br;
	static InputStream is;
	static ObjectInputStream ois;
	static Socket conSocket;
	static Scanner sc = new Scanner(System.in);
	static ObjectOutputStream oos;
	static OutputStream os;
	static Hashtable<String, String> userList = new Hashtable<String, String>();
	static ArrayList<String> users = new ArrayList<String>();
	static Random random = new Random();
	static InetAddress ia;
	
	static Hashtable<String, SecretKey> sessionKeyTable1 = new Hashtable<String, SecretKey>();
	static Hashtable<String, SecretKey> sessionKeyTable2 = new Hashtable<String, SecretKey>();
	static Hashtable<String, SecretKey> sessionKeyTable3 = new Hashtable<String, SecretKey>();
	

	public static void main(String[] args) {
		System.out.println("\t\t\t\t\t\t\tAUTHENTICATION SERVER NODE");
		
		try {
			serverSocket = new ServerSocket(6000);
			conSocket = serverSocket.accept();
			is = conSocket.getInputStream();
			ois = new ObjectInputStream(is);
			os = conSocket.getOutputStream();
			oos = new ObjectOutputStream(os);

		} catch (IOException e) {
			System.out.println(e.toString());
		}
		
		System.out.println(" Authentication Server is UP and connected\n");
		MailerAuthenticationServer mas = new MailerAuthenticationServer();
		Thread t = new Thread(mas);
		t.start();

		int option;
		do {
			System.out.println("0.Exit");
			System.out.println("1.Generate a Server Key and Show Server Key");
			System.out.println("2.Create new login");
			System.out.println("3.Generate accessKey for new user");
			System.out.print("Enter the option:");
			option = sc.nextInt();
			switch (option) {
			case 0: {
				System.exit(0);
			}
			case 1: {
				AuthenticationNode.keyGenerator();
				System.out.println("Server Key:\n"+AuthenticationNode.loadKey("serverKey"));
				continue;
			}
			
			case 2: {
				System.out.print("Enter the Username:\t");
				String userName = sc.next();
				System.out.print("Enter the Password:\t");
				String password = sc.next();
				userList.put(userName, password);
				System.out.println("Hash table:"+AuthenticationNode.userList);
				AuthenticationNode.passwordKeyGenerator(userName, password);
				continue;
			}
			case 3: {
				System.out.print("Enter the username:\t");
				String userName = sc.next();
				users.add(userName);
				AuthenticationNode.keyGenerator();
				SecretKey accessKey = AuthenticationNode.loadKey("accessKey");
				AuthenticationNode.storeKey(accessKey, userName + "AccessKey");
				System.out.println("Access key generated:\n"+accessKey.toString());
				continue;
			}

			}

		} while (option != 0);

	}

	static Object deserialize(byte[] bytes) throws IOException,
			ClassNotFoundException {
		ByteArrayInputStream b = new ByteArrayInputStream(bytes);
		ObjectInputStream o = new ObjectInputStream(b);
		return o.readObject();
	}

	public static void passwordKeyGenerator(String userName, String password) {
		// Generates New Key
		Security.addProvider(new FlexiCoreProvider());
		try {

			KeyGenerator keyGen = KeyGenerator.getInstance("AES", "FlexiCore");
			SecretKey secKey = keyGen.generateKey();
			AuthenticationNode.storeKey(secKey, userName);
			AuthenticationNode.storeKey(secKey, password);
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.toString());
		} catch (NoSuchProviderException e) {
			System.out.println(e.toString());
		}

	}

	
	private static String algorithm = "PBEWithMD5AndDES";
	private static Cipher alternativeCipher = null;
	
	public static byte[] alternativeEncrypt(byte[] b, String pwd) {
		byte[] output = new byte[3024];
		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);

			byte[] pass = pwd.getBytes();
			SecretKey key = factory.generateSecret(new DESedeKeySpec(pass));
			alternativeCipher = Cipher.getInstance(algorithm);

			alternativeCipher.init(Cipher.ENCRYPT_MODE, key);
			output = alternativeCipher.doFinal(b);

		} catch (Exception e) {
			System.out.println(e.toString());
		}
		return output;
	}

	public static byte[] alternatedecrypt(byte[] b, String pwd) {
		byte[] output = new byte[3024];
		try {

			SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);

			byte[] pass = pwd.getBytes();
			SecretKey key = factory.generateSecret(new DESedeKeySpec(pass));

			alternativeCipher.init(Cipher.DECRYPT_MODE, key);
			alternativeCipher = Cipher.getInstance(algorithm);
			output = alternativeCipher.doFinal(b);

		} catch (Exception e) {
			System.out.println(e.toString());
		}
		return output;
	}


	
	
	public static byte[] toByteStream(Object o) {
		byte[] convertedObject = new byte[2048];
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(baos);
			oos.writeObject(o);
			oos.flush();
			convertedObject = baos.toByteArray();
		} catch (IOException e) {
			System.out.println("Problem in converting object: " + e.toString());
		}

		return convertedObject;

	}

	public static SecretKey dummyKeyGenerator() {
		// Generates New Key
		Security.addProvider(new FlexiCoreProvider());
		SecretKey secKey = null;
		try {

			KeyGenerator keyGen = KeyGenerator.getInstance("AES", "FlexiCore");
			secKey = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.toString());
		} catch (NoSuchProviderException e) {
			System.out.println(e.toString());
		}
		return secKey;

	}

	public static byte[] generateHash(byte[] inputBuffer, SecretKey Key) {
		// Generate Message Digest
		String inputHash = new String(inputBuffer) + Key;
		byte[] inputHashBuffer = inputHash.getBytes();
		byte[] digest = new byte[1024];
		try {
			MessageDigest md = MessageDigest.getInstance("MD5", "FlexiCore");
			md.update(inputHashBuffer);
			digest = md.digest();
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.toString());
		} catch (NoSuchProviderException e) {
			System.out.println(e.toString());
		}
		return digest;
	}

	public static byte[] newpacker(byte[] inputBuffer) {

		SecretKey secKey;

		byte[] outputBuffer;

		secKey = AuthenticationNode.loadKey("serverKey");

		outputBuffer = AuthenticationNode.encryptMsg(inputBuffer, secKey);

		return outputBuffer;
	}

	public static void keyGenerator() {
		// Generates New Key
		Security.addProvider(new FlexiCoreProvider());
		try {

			KeyGenerator keyGen = KeyGenerator.getInstance("AES", "FlexiCore");
			SecretKey secKey = keyGen.generateKey();
			AuthenticationNode.storeKey(secKey, "serverKey");
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.toString());
		} catch (NoSuchProviderException e) {
			System.out.println(e.toString());
		}

	}

	public static void storeKey(SecretKey secKey, String key) {
		// Stores the key in serverKey file
		File file = new File(key);
		try {
			FileOutputStream fos = new FileOutputStream(file);
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			oos.writeObject(secKey);
			oos.close();
			fos.close();
		} catch (IOException e) {
			System.out.println(e.toString());
		}
	}

	public static SecretKey loadKey(String key) {
		// Load the key for encryption/decryption
		FileInputStream fis;
		SecretKey secKey =null;
		try {
			fis = new FileInputStream(key);
			ObjectInputStream ois = new ObjectInputStream(fis);
			secKey = (SecretKey) ois.readObject();
			ois.close();
			fis.close();

		} catch (IOException e) {
			System.out.println(e.toString());
			System.out.println("Cannot find the key");
		} catch (ClassNotFoundException e) {
			System.out.println(e.toString());
		}
		return secKey;

	}

	public static byte[] encryptMsg(byte[] plainBuffer, SecretKey secKey) {
		// Method for encryption
		Security.addProvider(new FlexiCoreProvider());
		byte[] encryptBuffer = new byte[1024];
		try {
			Cipher cipher = Cipher.getInstance("AES128_CBC", "FlexiCore");
			cipher.init(Cipher.ENCRYPT_MODE, secKey);

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			CipherOutputStream cos = new CipherOutputStream(baos, cipher);
			DataOutputStream dos = new DataOutputStream(cos);
//			System.out.println("buffer length:\t" + plainBuffer.length
//					+ "Key:\t" + secKey);
			dos.write(plainBuffer, 0, plainBuffer.length);
			dos.flush();
			dos.close();
			encryptBuffer = baos.toByteArray();
			cos.close();
			baos.close();
		} catch (Exception e) {
			System.out.println(e.toString());
		}
		return encryptBuffer;
	}

	public static byte[] decryptMsg(byte[] encryptBuffer, SecretKey secKey) {
		// Method for decryption

		Security.addProvider(new FlexiCoreProvider());
		byte[] plainBuffer = new byte[1024];
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES128_CBC", "FlexiCore");
			cipher.init(Cipher.DECRYPT_MODE, secKey);
			ByteArrayInputStream bais = new ByteArrayInputStream(encryptBuffer);
			CipherInputStream cis = new CipherInputStream(bais, cipher);
			DataInputStream dis = new DataInputStream(cis);
			dis.read(plainBuffer, 0, plainBuffer.length);
			dis.close();

		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.toString());
		} catch (IOException e) {
			System.out.println(e.toString());
		} catch (InvalidKeyException e) {
			System.out.println(e.toString());
		} catch (NoSuchPaddingException e) {
			System.out.println(e.toString());
		} catch (NoSuchProviderException e) {
			System.out.println(e.toString());
		}

		return plainBuffer;
	}

}
