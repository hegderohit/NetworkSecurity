package com.netsec.utd;

import java.util.HashMap;

public class ClientProfile {
	/**
	 * Client id
	 */
	int clientId;
	/**
	 * Client name
	 */
	String clientName;
	/**
	 * Client account number
	 */
	int accountNumber;
	/**
	 * balance stored
	 */
	int balance;
	/**
	 * hashmap to store the recent history of the client purchase
	 */
	HashMap<Integer, String> recentActivity = new HashMap<>();

	public int getClientId() {
		return clientId;
	}

	public String getClientName() {
		return clientName;
	}

	public int getAccountNumber() {
		return accountNumber;
	}

	public int getBalance() {
		return balance;
	}

	public HashMap<Integer, String> getRecentActivity() {
		return recentActivity;
	}

	public void setClientId(int id) {
		this.clientId = id;
	}

	public void setClientName(String userName) {
		this.clientName = userName;
	}

	public void setAccountNumber(int accountNumber) {
		this.accountNumber = accountNumber;
	}

	public void setBalance(int balance) {
		this.balance = balance;
	}

	public void setRecentActivity(HashMap<Integer, String> recentActivity) {
		this.recentActivity = recentActivity;
	}

}
