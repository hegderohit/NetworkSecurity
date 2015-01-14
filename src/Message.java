import java.io.Serializable;

public class Message implements Serializable {

	private static final long serialVersionUID = 1L;
	int msgType;
	String userName;
	byte[] check;
	byte[] passwordBuffer;
	byte[] msgBuffer;
	byte[] buffer;
	byte[] status;
	byte[] hashCheque;
	long validity;
	byte[] token;
	byte[] sessionByte;
	byte[] sessionCLI_EMSByte;
	byte[] sessionEMS_FSByte ;
	byte[] sessionCLI_FSByte;
	long Nonce;
	String filename;
	byte[] hashbuffer;
	byte[] fileByte;
	byte[] filecontent;
	
	
	public Message(int msgType) {
		this.msgType = msgType;
	}
//1 LOGIN TO AUTHENTICATION SERVER MESSAGE
// ALSO, MESSAGE FROM EMS TO CLIENT NODE: MESSAGE 6	
	public Message(int msgType,String userName, byte[] filecontent, long Nonce) {
		this.msgType = msgType;
		this.userName=userName;
		this.filecontent = filecontent;
		this.Nonce =Nonce;
	}

//2	 MESSAGE FROM FILE SERVER TO EMS; Message 5; 5PARA
		public Message(int msgType, String userName, String filename, byte[] filecontent,long Nonce) {
			this.msgType = msgType;
			this.userName = userName;
			this.filename=filename;
			this.filecontent = filecontent;		
			this.Nonce =Nonce;
		}
//3	
	public Message(byte[] sessionByte, int msgType, String userName, long validity, byte[] buffer,
			byte[] token, long Nonce) {
		this.msgType = msgType;
		this.userName = userName;
		this.validity = validity;
		this.buffer = buffer;
		this.token = token;
		this.sessionByte = sessionByte;
		this.Nonce =Nonce;
	
	}
//4
	public Message(int msgType, String userName, long validity, byte[] buffer,
			byte[] token, long Nonce) {
		this.msgType = msgType;
		this.userName = userName;
		this.validity = validity;
		this.buffer = buffer;
		this.token = token;// 
		this.Nonce =Nonce;
	}
//5 : This Message is received from EMS to Client: Message 6; 6para
	public Message(int msgType, String userName, byte[] check, byte[] buffer, byte[] fileByte, long Nonce) {
		super();
		this.msgType = msgType;
		this.userName = userName;
		this.check = check;
		this.buffer = buffer;
		this.fileByte = fileByte;
		this.Nonce =Nonce;
	}

// 6 :This message is from client to Authentication server= Message 1; 7 para
	public Message(int msgType, String userName, byte[] check,
			byte[] passwordBuffer, byte[] hashBuffer, byte[] buffer, long Nonce) {
		super();
		this.msgType = msgType;
		this.userName = userName;
		this.check = check;
		this.passwordBuffer = passwordBuffer;
		this.hashbuffer = hashBuffer;
		this.buffer = buffer;
		this.Nonce =Nonce;

	}
	
//7: THIS is message from authentication server to client;10 para
	public Message(int msgType, String userName, byte[] status,long validity,byte[] token, byte[] buffer, byte[] sessionCLI_EMSByte,byte[] sessionEMS_FSByte,
			byte[] sessionCLI_FSByte,long Nonce) {
		super();
		this.msgType = msgType;
		this.userName = userName;
		this.status = status;
		this.validity = validity;
		this.token=token;
		this.buffer = buffer;
		this.sessionCLI_EMSByte = sessionCLI_EMSByte;
		this.sessionEMS_FSByte = sessionEMS_FSByte;
		this.sessionCLI_FSByte = sessionCLI_FSByte;
		this.Nonce =Nonce;
	}
	
//8: This message is from client to EMS server= Message 3; 10 para
	public Message(int msgType, String userName, byte[] check,String filename, byte[] hashBuffer, byte[] buffer, byte[] sessionCLI_EMSByte,byte[] sessionEMS_FSByte,
			byte[] sessionCLI_FSByte, long Nonce) {
		super();
		this.msgType = msgType;
		this.userName = userName;
		this.check = check;
		this.filename = filename;
		this.hashbuffer = hashBuffer;
		this.buffer = buffer;
		this.sessionCLI_EMSByte = sessionCLI_EMSByte;
		this.sessionEMS_FSByte = sessionEMS_FSByte;
		this.sessionCLI_FSByte = sessionCLI_FSByte;
		this.Nonce =Nonce;

	}
//9: This message is from EMS to FILE server= Message 4; 9 para
	public Message(int msgType, String userName, byte[] check,String filename, byte[] hashBuffer, byte[] buffer,byte[] sessionEMS_FSByte,
			byte[] sessionCLI_FSByte, long Nonce) {
		super();
		this.msgType = msgType;
		this.userName = userName;
		this.check = check;
		this.filename = filename;
		this.hashbuffer = hashBuffer;
		this.buffer = buffer;
		this.sessionEMS_FSByte = sessionEMS_FSByte;
		this.sessionCLI_FSByte = sessionCLI_FSByte;
		this.Nonce =Nonce;

	}

}

