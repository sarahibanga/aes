fn main() {

}


#[cfg(test)]
mod tests {
	#[test]
	fn example1() {
		let key = "5468617473206D79204B756E67204675"; //128-bit key (in hexadecimal)
		let plaintext = "544F4E20776E69546F656E772020656F"; // in hexadecimal
		
		println!("Example 1:");
		println!("Key: {}", key);
		println!("Plaintext: {}", plaintext);
		
		// TODO: Make AES constructor
		let cipher = AES(key, plaintext); 

		println!("Ciphertext:");
		// TODO: Use Rust loop. 
		for(int ii=0;ii<cipher.length();ii+=2)
			println!("{} "cipher.substring(ii, ii+2));
		println!(""); // TODO: Remove

		let expected_ciphertext = "9A 1A F3 5C 98 23 EE 1C C8 88 A1 C8 09 04 60 B2";
		assert_eq!(expected_ciphertext, cipher);
	}

	#[test]
	fn example2() {
		// Source: Textbook Ch.5.5 (p.169)
		let	key = "0f1571c947d9e8590cb7add6af7f6798"; //128-bit key (in hexadecimal)
		let plaintext  ="0123456789abcdeffedcba9876543210"; // in hexadecimal
		
		println!("Example 2:");
		println!("Key: {}", key);
		println!("Plaintext: {}", plaintext);

		// TODO: Make AES constructor
		let cipher = AES(key,plaintext);
		println!("Ciphertext:");
		// TODO: Use Rust loop.
		for(int ii=0;ii<cipher.length();ii+=2)
			println!("{} ", cipher.substring(ii, ii+2));
		println!(""); // TODO: Remove

		let expected_ciphertext = "FF 0B 84 4A 08 53 BF 7C 69 34 AB 43 64 14 8F B9";
		assert_eq!(expected_ciphertext, cipher);
	}
}


