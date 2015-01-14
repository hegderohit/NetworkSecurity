import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.core.FlexiCoreProvider;


//THIS  IS THREAD BETWEEN EMS AND FILE SERVER
class MailerEMSServer implements Runnable {

	public static synchronized void send(Message m) {
		try {
			EMSNode.objectOutputStreamServer.writeObject(m);
			EMSNode.objectOutputStreamServer.flush();
			System.out.println("Sent");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void run() {
		try {
			Message m = (Message) EMSNode.objectInputStreamServer
					.readObject();

			if (m.msgType == 2) {
				System.out.println("\t\t\t\t\t**********Message 5**********");
				
				System.out.println("Received DaTA from SERVER NODE\n");
				System.out.println("Received Message (Encrypted):\t" + new String(m.filecontent));
				
				//SEND THIS MESSAGE TO CLIENT
				Message filecontentMessage = new Message(1, m.userName,m.filecontent, EMSNode.random.nextLong());
				System.out.println("\nSending to Client:" +m.userName+ ".......\n");
				MailerEMSClient.send(filecontentMessage);
				
				}
			
		} catch (IOException e) {
			System.out.println(e.toString());
		} catch (ClassNotFoundException e) {
			System.out.println(e.toString());
		}

	}
}

//THIS IS THE THREAD BETWEEN EMS AND CLIENT

class MailerEMSClient implements Runnable {

	public static synchronized void send(Message m) {
		try {
			
			EMSNode.oos.writeObject(m);
			EMSNode.oos.flush();
			System.out.println("Sent\n");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void run() {
		while (true) {
			try {

				Message m = (Message) EMSNode.ois.readObject();
				if (m != null) {
					System.out.println("\t\t\t\t\t**********Message 3**********");
					System.out.println("\nReceived Message From:\t" + m.userName);
				}
				if (m.msgType == 8) {
					
					System.out.println("Received Filename:\t"+m.filename);
					
					
					System.out.println("Received Hash:\t"+ ByteUtils.toHexString(m.hashbuffer));
					byte[] hashBuffer = EMSNode.generateHash(m.userName.getBytes(),EMSNode.loadKey("serverKey"));
					System.out.println("Verified Hash:\t"+ ByteUtils.toHexString(hashBuffer));
					//String s1 = ByteUtils.toHexString(hashBuffer);
					//String s2 = ByteUtils.toHexString(m.hashbuffer);

					/*if (!s1.trim().equals(s2.trim())) {
						System.out.println("Message Integrity compromised");
						MailerEMSServer.send(m);
						continue;
					}*/
					System.out.println("Received Message (Encrypted):\t" + new String(m.buffer));
					System.out.println("Received Session Key between Client and EMS:\t"+m.sessionCLI_EMSByte);
			
					Message messageToServer = new Message(9, m.userName,m.check,m.filename, m.hashbuffer,m.buffer,m.sessionEMS_FSByte,
					m.sessionCLI_FSByte, EMSNode.random.nextLong());
					System.out.println("Message is sent to the SERVER NODE \n");	
						//SEND WRAPPED MESSAGE TO FILE SERVER
					MailerEMSServer.send(messageToServer);
					
					continue;
				}

				System.out.println("UserName:\t" + m.userName);
				System.out.println("Message Type:\t" + m.msgType);
				SecretKey userKey = EMSNode.loadKey(m.userName + "AccessKey");
				byte[] decryptedInnerMeaage = EMSNode.decryptMsg(m.check, userKey);

				byte[] checkBuffer = EMSNode.generateHash(
						m.userName.getBytes(), userKey);
				String s1 = ByteUtils.toHexString(checkBuffer);
				String s2 = ByteUtils.toHexString(m.buffer);
				System.out.println("Verified Hash:\t" + s1);
				System.out.println("Received Hash:\t" + s2);
				if (!s1.trim().equals(s2.trim())) {
					System.out.println("Message integrity compromised");
					continue;
				}

				if (m.msgType == 0) {
					EMSNode.conSocket.close();
				}

				System.out.println("Authenticated:"+ new String(decryptedInnerMeaage));
				if(!EMSNode.users.contains(m.userName)){
					System.out.println("Unauthenticated User\n Sorry I cant send your message");
					continue;
				}
			} catch (IOException e) {
				System.out.println(e.toString());
				e.printStackTrace();
				System.out.println("You are not an Authentic User!!!");
			} catch (ClassNotFoundException e) {
				System.out.println(e.toString());
			}
		}

	}

}

public class EMSNode {

	static ServerSocket accessSocket;
	static BufferedReader br;
	static Scanner sc = new Scanner(System.in);
	static ArrayList<String> users = new ArrayList<String>();
	static Socket conSocket;
	static InputStream is;
	static ObjectInputStream ois;
	static OutputStream os;
	static ObjectOutputStream oos;
	static Random random = new Random();
	static Socket accessServerSocket;
	static OutputStream outputStreamServer;
	static ObjectOutputStream objectOutputStreamServer;
	static InputStream inputStreamServer;
	static ObjectInputStream objectInputStreamServer;
	static InetAddress ia;

	public static void main(String[] args) {
		System.out.println("\t\t\t\t\t\tEMS NODE");
		System.out.print("Enter the IP Address of FINANCE SERVER:\t");
		String ipString = sc.next();
		try {
			ia = InetAddress.getByName(ipString);
		} catch (UnknownHostException e) {
			System.out.println(e.toString());
		}
		try {
			accessServerSocket = new Socket(ia, 5555);
			outputStreamServer = accessServerSocket.getOutputStream();
			objectOutputStreamServer = new ObjectOutputStream(
					outputStreamServer);
			inputStreamServer = accessServerSocket.getInputStream();
			objectInputStreamServer = new ObjectInputStream(inputStreamServer);
		} catch (IOException e) {
			System.out.println(e.toString());
		}
		
		System.out.print("Enter the IP Address of MARKETING SERVER:\t");
		String ipString2 = sc.next();
		try {
			ia = InetAddress.getByName(ipString2);
		} catch (UnknownHostException e) {
			System.out.println(e.toString());
		}
		try {
			accessServerSocket = new Socket(ia, 6666);
			outputStreamServer = accessServerSocket.getOutputStream();
			objectOutputStreamServer = new ObjectOutputStream(
					outputStreamServer);
			inputStreamServer = accessServerSocket.getInputStream();
			objectInputStreamServer = new ObjectInputStream(inputStreamServer);
		} catch (IOException e) {
			System.out.println(e.toString());
		}
		
		int option;
		do {
			System.out.println("0.Exit");
			System.out.println("1.Start EMS ...\n");
			System.out.print("Enter the Option:");
			option = sc.nextInt();

			switch (option) {
			case 0: {
				System.exit(0);
			}
			case 1: {
				try {
					accessSocket = new ServerSocket(4444);
					conSocket = accessSocket.accept();
					is = conSocket.getInputStream();
					ois = new ObjectInputStream(is);
					os = conSocket.getOutputStream();
					oos = new ObjectOutputStream(os);

				} catch (IOException e) {
					System.out.println(e.toString());
				}
				MailerEMSClient MailerEMSClient = new MailerEMSClient();
				Thread MailerEMSClientThread = new Thread(MailerEMSClient);
				MailerEMSClientThread.start();
				
				MailerEMSServer MailerEMSServer = new MailerEMSServer();
				Thread masThread = new Thread(MailerEMSServer);
				masThread.start();
				
				
				
			

			}

			}
		} while (option != 0);

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

	
	public static byte[] newDecrypter(byte[] inputBuffer) {

		SecretKey secKey;

		byte[] outputBuffer;

		secKey = EMSNode.loadKey("serverKey");

		outputBuffer = EMSNode.decryptMsg(inputBuffer, secKey);

		return outputBuffer;
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

	// public static Message packerToServer(int msgType, InnerMessage im) {
	// byte[] b = EMSNode.toByteStream(im);
	// SecretKey secKey;
	// Message m = null;
	//
	// secKey = EMSNode.loadKey("serverKey");
	// byte[] encryptedInnerMessage = EMSNode.encryptMsg(b, secKey);
	// m = new Message(msgType, im.userName, encryptedInnerMessage);
	//
	// return m;
	// }

	public static byte[] toByteStream(Object o) {
		byte[] convertedObject = new byte[2048];
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(baos);
			oos.writeObject(o);
			convertedObject = baos.toByteArray();
		} catch (IOException e) {
			System.out.println("Problem in converting object: " + e.toString());
		}

		return convertedObject;

	}

	static Object deserialize(byte[] bytes) throws IOException,
			ClassNotFoundException {
		ByteArrayInputStream b = new ByteArrayInputStream(bytes);
		ObjectInputStream o = new ObjectInputStream(b);
		return o.readObject();
	}

	static byte[] encryptMsg(byte[] plainBuffer, SecretKey secKey) {
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

	static byte[] decryptMsg(byte[] encryptBuffer, SecretKey secKey) {
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

	static byte[] generateHash(byte[] inputBuffer, SecretKey Key) {
		// Generate Message Digest
		String inputHash = new String(inputBuffer) + Key;
		byte[] inputHashBuffer = inputHash.getBytes();
		byte[] digest = new byte[1024];
		try {
			MessageDigest md = MessageDigest.getInstance("MD5", "FlexiCore");
			md.update(inputHashBuffer);
			digest = md.digest();
			// System.out.println("Digest:" + ByteUtils.toHexString(digest));
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.toString());
		} catch (NoSuchProviderException e) {
			System.out.println(e.toString());
		}
		return digest;
	}

	static void storeInFile(byte[] inputBuffer, String fileName) {
		File file = new File(fileName);
		BufferedWriter bw;
		try {
			bw = new BufferedWriter(new FileWriter(file));
			bw.write(ByteUtils.toHexString(inputBuffer));
			bw.close();

		} catch (IOException e) {
			System.out.println(e.toString());
		}

	}

	static void keyGenerator() {
		// Generates New Key
		Security.addProvider(new FlexiCoreProvider());
		try {

			KeyGenerator keyGen = KeyGenerator.getInstance("AES", "FlexiCore");
			SecretKey secKey = keyGen.generateKey();
			EMSNode.storeKey(secKey, "accessKey");
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.toString());
		} catch (NoSuchProviderException e) {
			System.out.println(e.toString());
		}

	}

	public static SecretKey loadKey(String key) {
		// Load the key for encryption/decryption
		FileInputStream fis;
		SecretKey secKey = null;
		try {
			fis = new FileInputStream(key);
			ObjectInputStream ois = new ObjectInputStream(fis);
			secKey = (SecretKey) ois.readObject();
			ois.close();
			fis.close();

		} catch (ClassNotFoundException e) {
			System.out.println(e.toString());
		} catch (IOException e) {
			System.out.println("Unauthenticated User");
			secKey = ClientNode.dummyKeyGenerator();

		}

		return secKey;

	}

	static void storeKey(SecretKey secKey, String key) {
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

}
