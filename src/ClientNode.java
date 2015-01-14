import java.io.IOException;

import java.security.InvalidKeyException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.core.FlexiCoreProvider;


class MailerClientNode implements Runnable {

	public static synchronized void send(Message m) {
		try {
			
			
			ClientNode.oos.writeObject(m);
			ClientNode.oos.flush();
		
			
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void run() {

		
			// TODO Auto-generated method stub
			try {
				
				Message m = (Message) ClientNode.ois.readObject();
				
				if (m.msgType == 7) {
					System.out.println("\t\t\t\t\t**********Message 2**********");
					System.out.println("\n user:\t" + m.userName);
					System.out.println("Received token:\t"+ ByteUtils.toHexString(m.token));
					byte[] hashBuffer = AuthenticationNode.generateHash(m.userName.getBytes(),ClientNode.loadKey("serverKey"));
					System.out.println("Verified token:\t"+ ByteUtils.toHexString(hashBuffer));
					ClientNode.validity = m.validity;
					
					ClientNode.sessionKey1 = (SecretKey) ClientNode.deserialize(m.sessionCLI_EMSByte);
					System.out.println("Session Key1 (between ClientNode and EMS):"+ClientNode.sessionKey1.toString());
					ClientNode.sessionKey2 = (SecretKey) ClientNode.deserialize(m.sessionEMS_FSByte);
					System.out.println("\nSession Key2 (between EMS and fileserver):"+ClientNode.sessionKey2.toString());
					ClientNode.sessionKey3 = (SecretKey) ClientNode.deserialize(m.sessionCLI_FSByte);
					System.out.println("\nSession Key3 (between ClientNode and fileserver):"+ClientNode.sessionKey3.toString());
					System.out.println(" Client is Authenticated.......\n");
					System.out.println("\nEnter options:");
					            
				}
				
				if(m.msgType== 1)
				{
					System.out.println("\t\t\t\t\t**********Message 6**********");
					System.out.println("\n user:\t" + m.userName);
					
					// Decryption of File content
					byte[] newfilecontent=ClientNode.newpacker(m.filecontent);
					String value= new String(newfilecontent, "UTF-8");
					System.out.println(value);
					//System.out.println("File Received and Stored by Client ");
					//Scanner sc = new Scanner(System.in);
			        try {
			           // System.out.println("Enter the filename to store:");
			            //String file_to_store = sc.next();
			            BufferedWriter out = new BufferedWriter (new FileWriter ("C:\\Users\\Radhika\\workspace\\netsec\\" +"ReceivedFile"));
			            out.write(value);
			            out.close();
			          //  File newTextFile = new File("C:\\Users\\Radhika\\workspace\\netsec\\" +file_to_store);
			           // fileWriter = new FileWriter(newTextFile);
			         //   fileWriter.write(value);
			          //  fileWriter.close();
			        } catch (IOException ex) {
			            ex.printStackTrace();
			        } 
				
			}					
				
				

			} catch (IOException e) {
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				System.out.println(e.toString());
			}
		}

}



public class ClientNode {

	public static SecretKey sessionKey3;//between ClientNode and fileserver
	public static SecretKey sessionKey1;//between ClientNode and ems
	public static SecretKey sessionKey2;//between ems and fileserver
	static Socket s;
	static OutputStream os;
	static ObjectOutputStream oos;
	static Scanner sc = new Scanner(System.in);
	static InputStream is;
	static ObjectInputStream ois;
	static Random random = new Random();
	static long validity;
	static byte[] token;
	static InetAddress ia;
	public static boolean mutex=true;
	
	
	public static void main(String[] args) 
	{
		System.out.println("\t\t\t\t\t\t\tCLIENT NODE");
		
		
		int option;
		
		
		do {
			
			{
				
			System.out.println("0.Exit");
			System.out.println("1.Login to the Server");
			System.out.println("2.Contact EMS");
			System.out.print("Enter the option:");
			option = sc.nextInt();
			
			
			switch (option) 
			{
			case 0: 
			{
				Message m = new Message(0);
				MailerClientNode.send(m);
				System.exit(0);
			}
			case 1:
			{
				System.out.print("Enter the IP Address of Authentication Node:\t");
				String ipString = sc.next();
				try 
				{
					ia = InetAddress.getByName(ipString);
				} 
				catch (UnknownHostException e) 
				{
					System.out.println(e.toString());
				}

				try 
				{
					s = new Socket(ia, 6000);
					os = s.getOutputStream();
					oos = new ObjectOutputStream(os);
					is = s.getInputStream();
					ois = new ObjectInputStream(is);

				} 
				catch (IOException e) 
				{
					e.printStackTrace();
				}
				System.out.println("Register with Authentication server first.....\t");
				System.out.print("Enter the Username:\t");
				String userName = sc.next();
				System.out.print("Enter the Password:\t");
				String password = sc.next();
				byte[] passwordBuffer = password.getBytes();
				
				MailerClientNode mc = new MailerClientNode();
				Thread mcThread = new Thread(mc);
				mcThread.start();
				try 
				{
					SecretKey secKey = ClientNode.loadKey(password);
					System.out.println("Password Key:\t" + secKey);
					byte[] encryptedPasswordBuffer = ClientNode.encryptMsg(passwordBuffer, secKey);
					
					int msgType = 6;
					byte[] hashbuffer = ClientNode.generateHash(userName.getBytes(),ClientNode.loadKey(userName + "AccessKey"));
					System.out.println("Generated Hash:\t"+ByteUtils.toHexString(hashbuffer));
					Message m = ClientNode.newpacker(msgType, userName, encryptedPasswordBuffer, hashbuffer);
					
					//Send Message1 to Authentication Server
					
					MailerClientNode.send(m);
					
					break;
				} 
				catch (Exception e) 
				{
					System.out.println(e.toString());
				}

				
			}
			case 2:
			{
				if(validity>0)
				{
					System.out.print("Enter the IP Address of EMS:\t");
					String ipString = sc.next();
					try 
					{
					ia = InetAddress.getByName(ipString);
					} 
					catch (UnknownHostException e) 
					{
					System.out.println(e.toString());
					}

					try 
					{
					s = new Socket(ia, 4444);
					os = s.getOutputStream();
					oos = new ObjectOutputStream(os);
					is = s.getInputStream();
					ois = new ObjectInputStream(is);

					} 
					catch (IOException e) 
					{
					e.printStackTrace();
					}
				
					System.out.print("Enter the Username:\t");
					String userName = sc.next();
					System.out.print("Enter the Filename:\t");
					String filename = sc.next();
					//byte[] filenameBuffer = filename.getBytes();
				
					MailerClientNode mc = new MailerClientNode();
					Thread mcThread = new Thread(mc);
					mcThread.start();
					try 
					{
					int msgType = 8;
					//byte[] hashbuffer = ClientNode.generateHash(userName.getBytes(),ClientNode.loadKey(userName + "AccessKey"));
					byte[] hashbuffer = ClientNode.generateHash(userName.getBytes(),ClientNode.loadKey("serverKey"));
					System.out.println("Generated Hash:\t"+ByteUtils.toHexString(hashbuffer));
					Message m = ClientNode.newpacker(msgType, userName, filename, hashbuffer);
					
					//Send Message3 to EMS
					MailerClientNode.send(m);		
					
					} 
					catch (Exception e) 
					{
					System.out.println(e.toString());
					}

				}
				else
				{
					System.out.println("Login to authentication server first\n");
					
				}
			}
			
			}
			}
		}while (option!=0);
		
				
	}
	
	//MESSAGE PACKER FOR MESSAGE FROM CLIENT TO EMS
		private static Message newpacker(int msgType, String userName, String filename, byte[] hashbuffer) {
		
			SecretKey secKey;
			Message m = null;
			secKey = ClientNode.loadKey(userName + "AccessKey");
			byte[] check = userName.getBytes();
			byte[] encryptedCheck = ClientNode.encryptMsg(check, secKey);
			byte[] buffer = ClientNode.generateHash(userName.getBytes(), secKey);
			
			byte[] sessionCLI_EMSByte=ClientNode.toByteStream(sessionKey1);
			byte[] sessionEMS_FSByte=ClientNode.toByteStream(sessionKey2);
			byte[] sessionCLI_FSByte = ClientNode.toByteStream(sessionKey3);
		
			m = new Message(msgType, userName,  encryptedCheck, filename, hashbuffer, buffer,sessionCLI_EMSByte,
				sessionEMS_FSByte,sessionCLI_FSByte,ClientNode.random.nextLong());

			return m;
				
	}
		
//MESSAGE PACKER FOR MESSAGE FROM CLIENT TO AUTHENTICATION SERVER
		public static Message newpacker(int msgType, String userName,
				byte[] passwordBuffer, byte[] hashBuffer) {

			SecretKey secKey;
			Message m = null;
			//System.out.println("\nTESTING MSG NEW PACKER");
			secKey = ClientNode.loadKey(userName + "AccessKey");
			byte[] check = userName.getBytes();
			byte[] encryptedCheck = ClientNode.encryptMsg(check, secKey);
			byte[] buffer = ClientNode.generateHash(userName.getBytes(), secKey);
			m = new Message(msgType, userName, encryptedCheck, passwordBuffer,
					hashBuffer, buffer, ClientNode.random.nextLong());
			
			return m;
		}
		
		
// THIS FUNCTION STORES THE FILE CONTENT SENT BY FILE SERVER
		public static void storeFile(byte[] fileBuffer, String filename) {
			// Stores the key in serverKey file
			File file = new File(filename);
			try {
				FileOutputStream fos = new FileOutputStream(file);
				ObjectOutputStream oos = new ObjectOutputStream(fos);
				 oos.writeObject(fileBuffer);
				oos.close();
				fos.close();
			} catch (IOException e) {
				System.out.println(e.toString());
			}
		}
	/*	public static byte[] recieved_file (byte[] filebuffer, String filename)
		{
			
			byte[] mybytearray = new byte[1024];
			InputStream is = socket.getInputStream();
		    FileOutputStream fos = new FileOutputStream("received_file.txt");
		}
		*/
		
		
		
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

		public static Object deserialize(byte[] sessionByte) throws IOException, ClassNotFoundException {
			
			byte[] bytes=sessionByte;
			ByteArrayInputStream b = new ByteArrayInputStream(bytes);
			ObjectInputStream o=null;
			try {
				o = new ObjectInputStream(b);
			} catch (IOException e) {
				
				e.printStackTrace();
			}
			return o.readObject();

					
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
		
		public static byte[] encryptMsg(byte[] plainBuffer, SecretKey secKey) {
			// Method for encryption
			byte[] encryptBuffer = new byte[1024];
			Security.addProvider(new FlexiCoreProvider());
			try {
				Cipher cipher = Cipher.getInstance("AES128_CBC", "FlexiCore");
				cipher.init(Cipher.ENCRYPT_MODE, secKey);

				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				CipherOutputStream cos = new CipherOutputStream(baos, cipher);
				DataOutputStream dos = new DataOutputStream(cos);
				dos.write(plainBuffer, 0, plainBuffer.length);
				dos.flush();
				dos.close();
				encryptBuffer = baos.toByteArray();
				cos.close();
				baos.close();
			} catch (Exception e) {
				System.out.println(e.toString());
				System.out.println("in Encryption");
			}
			return encryptBuffer;
		}

		public static byte[] decryptMsg(byte[] encryptBuffer, SecretKey secKey) {
			// Method for decryption
			byte[] plainBuffer = new byte[1024];
			Security.addProvider(new FlexiCoreProvider());
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

		
		//FUNTION TO DECRYPT THE FILE CONTENT 
		public static byte[] newpacker(byte[] fileBuffer) {

			SecretKey secKey;

			byte[] outputBuffer;

			secKey = ServerNode.loadKey("serverKey");

			outputBuffer = ServerNode.decryptMsg(fileBuffer, secKey);

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
}