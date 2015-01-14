
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Hashtable;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import de.flexiprovider.core.FlexiCoreProvider;

 class MailerServerAccess implements Runnable {
       

	public static synchronized void send(Message m) {
		try{
			System.out.println("Sending........\n");
			ServerNode.oos.writeObject(m);
			ServerNode.oos.flush();
			System.out.println("Sent");
		} catch(IOException e)
        {
		e.printStackTrace();	
        }
	}

	@Override
	public void run() {
		while (true) {
			try 
               {
				Message m = (Message) ServerNode.ois.readObject();
                if (m != null)
                {   System.out.println("\t\t\t\t\t**********Message 4**********");            
					System.out.println("\nReceived Message From:\t"+m.userName);
				}
				if(m.msgType==9)  
				{
				
				System.out.println("Received Filename:\t"+m.filename);
				      
                //THIS MESSAGE IS WRAPPED AND SENT TO CLIENT THROUGH EMS
				byte[] FileContent= ServerNode.file_lookup(m.filename);
                int msgType=2;
            
                Message mes= new Message(msgType, m.userName,m.filename, ServerNode.newpacker(FileContent),ServerNode.random.nextLong());
                System.out.println("\nSending File to Client......\t");
                MailerServerAccess.send(mes);
				}
               }catch(IOException e)
               {
            	   e.printStackTrace();
               } catch (ClassNotFoundException e) {
				
				e.printStackTrace();
			}
				
		}
	}

	
 }
 
public class ServerNode
{
	static ServerSocket serverSocket;
	static BufferedReader br;
	static InputStream is;
	static ObjectInputStream ois;
	static Socket conSocket;
	static Scanner sc = new Scanner(System.in);
	static ObjectOutputStream oos;
	static OutputStream os;
	static Hashtable<String, String> userList = new Hashtable<String, String>();
	static Random random = new Random();
        

	static Hashtable<String, SecretKey> sessionKeyTable = new Hashtable<String, SecretKey>();

	public static void main(String[] args) {
		System.out.println("\t\t\t\t\t\t\tFINANCE SERVER NODE");
		try {
			serverSocket = new ServerSocket(5555);
			conSocket = serverSocket.accept();
			is = conSocket.getInputStream();
			ois = new ObjectInputStream(is);
			os = conSocket.getOutputStream();
			oos = new ObjectOutputStream(os);
		} catch (IOException e) {
			System.out.println(e.toString());
		}
		MailerServerAccess mas = new MailerServerAccess();
		Thread t = new Thread(mas);
		t.start();               
		System.out.println("WAITING\n");
	}

	

// FUNTION TO READ LARGE FILES INTO BUFFER	
	
	public static byte[] file_lookup(String filename) throws IOException{
		File f = new File(filename);
			if (!f.exists())
		      System.out.println("FileCopy: no such source file: " + filename);
		    if (!f.isFile())
		    	System.out.println("FileCopy: can't copy directory: " + filename);
		    if (!f.canRead())
		    	System.out.println("FileCopy: source file is unreadable: " + filename);
		 FileInputStream from = null;  // Stream to read from source
		 byte[] buffer = new byte[4096];  // A buffer to hold file contents
		    try {
		      from = new FileInputStream(filename);  // Create input stream	             
		      // Read a chunk of bytes into the buffer, then write them out, 
		      // looping until we reach the end of the file (when read() returns -1).
		      // Note the combination of assignment and comparison in this while
		      // loop.  This is a common I/O programming idiom.
		      while((from.read(buffer)) != -1); // Read bytes until EOF
		                   
		    }
		    // Always close the streams, even if exceptions were thrown
		    finally {
		      if (from != null) 
		    	  try { from.close(); } 
		      catch (IOException e) { ; }    
		    }
		    return buffer;
		  }
	
	
	
	static Object deserialize(byte[] bytes) throws IOException,ClassNotFoundException {
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
			ServerNode.storeKey(secKey, userName);
			ServerNode.storeKey(secKey, password);
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

	//TO ENCRYPT THE FILE CONTENT
	public static byte[] newpacker(byte[] fileBuffer) {
		SecretKey secKey;
		byte[] outputBuffer;
		secKey = ServerNode.loadKey("serverKey");
		outputBuffer = ServerNode.encryptMsg(fileBuffer, secKey);
		return outputBuffer;
	}

	
	public static void keyGenerator() {
		// Generates New Key
		Security.addProvider(new FlexiCoreProvider());
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES", "FlexiCore");
			SecretKey secKey = keyGen.generateKey();
			ServerNode.storeKey(secKey, "serverKey");
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
		SecretKey secKey = null;
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



    public static String[] getWords(String data,String splitChar)
	{
		String[] words = null;
		try
		{
			words = data.split(splitChar);
		}
		catch(Exception ex){
			ex.printStackTrace();
		}
		return words;
	}
    
 }
