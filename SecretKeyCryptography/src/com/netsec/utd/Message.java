package com.netsec.utd;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class Message implements Serializable {

	private static final long serialVersionUID = -1335351770906357695L;
	String Message_Type;

	// Authentication Message
	String nonce = null;
	String client_Name = null;
	String client_Id = null;

	public Message AuthenticationMessage(String nonce, String ClientName,
			String ClientId) {
		Message message = null;
		message.nonce = nonce;
		message.Message_Type = "AuthenticationMessage";
		message.client_Name = ClientName;
		message.client_Id = ClientId;
		return message;
	}

	@Override
	public String toString() {
		return "SecretObject [" + Message_Type + "," + client_Name + ","
				+ client_Id + "]";
	}

	// Catalog Request Message
	String Server_Name;
	String Server_Id;

	// Client req to Broker
	public Message ClientRequestMessage(String ClientName, String ClientId,
			String ServerName, String ServerId) {
		Message message = null;
		message.Message_Type = "ClientCatalogRequest";
		message.client_Name = ClientName;
		message.client_Id = ClientId;
		message.Server_Name = ServerName;
		message.Server_Id = ServerId;

		return message;
	}

	// Broker Req to Server
	public Message BrokerRequestMessage() {
		Message message = null;
		message.Message_Type = "BrokerCatalogRequest";
		return message;
	}

	// Catalog Reply Message
	ArrayList<Product> catalog_List;

	// server
	public Message ServerCatalogReplyMessage(List<Product> catalogList) {
		Message message = null;
		message.Message_Type = "ServerCatalogReplyMessage";
		message.catalog_List = (ArrayList<Product>) catalogList;
		return message;
	}

	// Broker Reply
	public Message BrokerCatalogReplyMessage(List<Product> catalogList) {
		Message message = null;
		message.Message_Type = "BrokerCatalogReplyMessage";
		message.catalog_List = (ArrayList<Product>) catalogList;
		return message;
	}

	// PurchaseProduct Message
	String productList;
	private double price;

	// Client to Broker
	public Message ClientPurchaseMessage(String ServerName, String ServerId, String products) {
		Message message = null;
		message.Message_Type = "ClientPurchaseMessage";
		message.Server_Name = ServerName;
		message.Server_Id = ServerId;
		message.productList = products;
		return message;
	}

	// Purchase Confirmation
	// server sends to broker who deducts and sends receipt to client
	public Message ServerPurchaseConfirmMessage(String ServerName, String ServerId, double price) {
		Message message = null;
		message.Message_Type = "ServerPurchaseConfirmMessage";
		message.Server_Name = ServerName;
		message.Server_Id = ServerId;
		message.price = price;
		return message;
	}
}
