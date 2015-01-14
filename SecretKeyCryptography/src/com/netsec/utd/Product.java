package com.netsec.utd;

/*
 * Defines the Name, price and category of products
 */

public class Product {
	String product_Name;
	String product_price;
	String product_category;

	public Product(String productName, String productPrice,
			String productCategory) {
		// TODO Auto-generated constructor stub
		this.product_Name = productName;
		this.product_price = productPrice;
		this.product_category = productCategory;
	}
}
