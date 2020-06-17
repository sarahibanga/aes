/*Sarah Ibanga */
/*References: 1) http://www.samiam.org/s-box.html
 * 			  2) https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon
 * 			  3) http://aescryptography.blogspot.com/2012/05/addroundkey-step.html
 * 			  4) https://en.wikipedia.org/wiki/Rijndael_MixColumns
 * 			  5) https://crypto.stackexchange.com/questions/2402/how-to-solve-mixcolumns
 * 			  6) https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf
 *			  7) Online AES Calculator(used to find/verify ciphertext):http://testprotect.com/appendix/AEScalc 
 *Progress: 10/20 - fixed bugs and now makekeys in correct
 * 			10/23 - fixed bugs with mixed columns
 *			10/29 - Fixed bugs within all segments 
 * */
				


import com.google.common.base.Charsets;
import com.google.common.base.Splitter;
import com.google.common.collect.Iterables;
import java.math.BigInteger;
import java.util.*;

import javax.xml.bind.DatatypeConverter;


public class cse178lab {
	
	
	/*Rijndael S-BOX*/
	static int sbox[] = { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe,
			0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72,
			0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04,
			0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c,
			0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20,
			0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33,
			0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
			0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e,
			0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde,
			0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4,
			0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba,
			0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5,
			0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69,
			0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
			0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
	
	static int rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,0x6c}; 
	
	static String cipher ="";
	
	public static void main(String[] args) {
	
	
	String key="";
	String plaintext="";
	String cipher="";
	
	/*Examples have plaintext and key in hexadecimal only*/
		
	/*Example 1 : 128 bit key (in hexadecimal) and plaintext (in hexadecimal)*/
		key="5468617473206D79204B756E67204675";//128-bit key
		plaintext = "544F4E20776E69546F656E772020656F"; 
		//ciphertext should be 9A 1A F3 5C 98 23 EE 1C C8 88 A1 C8 09 04 60 B2
		
		System.out.println("Example 1: ");
		System.out.println("Key: "+ key);
		System.out.println("Plaintext: "+plaintext);
		
		cipher = AES(key,plaintext);
		System.out.print("Ciphertext:");
		for(int ii=0;ii<cipher.length();ii+=2)
			System.out.print(cipher.substring(ii, ii+2)+" ");
		System.out.println();
		System.out.println();

/***********************************************************************************/		
	/*Example 2: Textbook Ch.5.5 (p.169)*/
		key ="0f1571c947d9e8590cb7add6af7f6798"; 
		plaintext="0123456789abcdeffedcba9876543210";
		//ciphertext should be FF 0B 84 4A 08 53 BF 7C 69 34 AB 43 64 14 8F B9
	
		
		
		System.out.println("Example 2: ");
		System.out.println("Key: "+ key);
		System.out.println("Plaintext: "+plaintext);
		
		cipher = AES(key,plaintext);
		System.out.print("Ciphertext:");
		for(int ii=0;ii<cipher.length();ii+=2)
			System.out.print(cipher.substring(ii, ii+2)+" ");
		System.out.println();
		System.out.println();

/***********************************************************************************/		
		
	}//ends main 
	
	
	public static String AES(String key, String plaintext){
		int i=0;
		/*padding if needed for text*/
		if(plaintext.length()%32 !=0){
			/*right pad message with spaces*/
			int pad_scale = 32-(plaintext.length()%32);
			while(i<pad_scale){
				plaintext +="0";
				i++;
			}
		}
			
		/*Split string into chunks*/
		String[] states =
			    Iterables.toArray(
			        Splitter
			            .fixedLength(32)
			            .split(plaintext),
			        String.class
			    );
		
		
		/*Loop over states and perform aes*/
		for(int w = 0; w<states.length;++w ){
				String []kw =new String[11];
				String state="";	
				state +=states[w];
				
				/*Step 1: Key expansion (Make the keys for all rounds + 1 more)*/
				
				kw[0]=key;
				//System.out.println(kw[0]);
				for(int ip=1; ip<11;++ip){
						kw [ip]=makekeys(kw[ip-1],ip); 
				}
				
				//Step 2 : Initial Round
				String init=addroundkey(kw[0],state);
				state = init;//update state
				
				//Step 3 : Rounds
				for(int h = 1; h <10; ++h){
						String h1=SubBytes(state);
						state=h1;//update state

						String h2=ShiftRows(state);
						state=h2;//update state

						String h3=MixColumns(state);
						state=h3;//update state
						String e = addroundkey(kw[h],state);
						state=e; //update state
				}
					

				//Step 4:Final Round(no Mix Columns)
					String h1=SubBytes(state);
					state=h1;//update state

					String h3=ShiftRows(state);
					state=h3;
					state = shelp(state);//read string by each column instead of across rows

					String e = addroundkey(kw[10],state);
					state=e; //update state

					//cipher text added to by columns	
					cipher=ciphermake(state);
					
					
		}
		return cipher;
	}
	public static String SubBytes(String state){
	//wikipedia:each byte is replaced with another according to a sbox
				String res="";
				ArrayList<String> w0 = new ArrayList<String>();//1st row
				ArrayList<String> w1 = new ArrayList<String>();//2nd row
				ArrayList<String> w2 = new ArrayList<String>();//3rd row
				ArrayList<String> w3 = new ArrayList<String>();//4th row
				for(int j=0; j<8;j+=2){
					w0.add(state.substring(j, j+2));
				}
				
				
				for(int j=8; j<16;j+=2){//
					w1.add(state.substring(j, j+2));  
				}
				
				for(int j=16; j<24;j+=2){
					w2.add(state.substring(j, j+2));
				}
				
				for(int j=24; j<32;j+=2){
					w3.add(state.substring(j, j+2));
				}
				
				for(int i1=0; i1<4;i1++){
					int tmp =sbox[Integer.parseInt(w0.get(i1),16)];
					w0.remove(i1);//remove current element at index
					w0.add(i1, String.format("%02X", tmp));//add to index and shift other elements			
				}
				for(int i1=0; i1<4;i1++){
					int tmp =sbox[Integer.parseInt(w1.get(i1),16)];
					w1.remove(i1);//remove current element at index
					w1.add(i1, String.format("%02X", tmp));//add to index and shift other elements			
				}
				for(int i1=0; i1<4;i1++){
					int tmp =sbox[Integer.parseInt(w2.get(i1),16)];
					w2.remove(i1);//remove current element at index
					w2.add(i1, String.format("%02X", tmp));//add to index and shift other elements			
				}
				for(int i1=0; i1<4;i1++){
					int tmp =sbox[Integer.parseInt(w3.get(i1),16)];
					w3.remove(i1);//remove current element at index
					w3.add(i1, String.format("%02X", tmp));//add to index and shift other elements			
				}
				for (String i:w0)
				     res+=i.toString();

				for (String i:w1)
				     res+=i.toString();
				for (String i:w2)
				     res+=i.toString();
				for (String i:w3)
				     res+=i.toString();
				return res;
	}
	
	public static String ShiftRows(String state){
		//wikipedia: last three state rows of the state are shifted cyclically by 1, 2, and 3 
		String res="";
		ArrayList<String> w0 = new ArrayList<String>();//1st row
		ArrayList<String> w1 = new ArrayList<String>();//2nd row
		ArrayList<String> w2 = new ArrayList<String>();//3rd row
		ArrayList<String> w3 = new ArrayList<String>();//4th row

		for(int j=0; j<8;j+=2){
			w0.add(state.substring(j, j+2));
		}
		
		for(int j=8; j<16;j+=2){//
			w1.add(state.substring(j, j+2));  
		}
		
		for(int j=16; j<24;j+=2){
			w2.add(state.substring(j, j+2));
		}
		
		for(int j=24; j<32;j+=2){
			w3.add(state.substring(j, j+2));
		}
		
		//First row is untouched
		//Second row is shifted cyclically to the left
		String temp = w1.get(0);
		w1.remove(0);
		w1.add(temp);
		//Third row is shifted cyclically to the left 2 times
		String temp2 = w2.get(0);
		w2.remove(0);
		w2.add(temp2); //now shifted once
		String temp3 = w2.get(0);
		w2.remove(0);
		w2.add(temp3); //now shifted twice
		//Third row is shifted cyclically to the left 2 times
		String temp4 = w3.get(0);
		w3.remove(0);
		w3.add(temp4); //now shifted once
		String temp5 = w3.get(0);
		w3.remove(0);
		w3.add(temp5); //now shifted twice
		String temp6 = w3.get(0);
		w3.remove(0);
		w3.add(temp6); //now shifted three times
		for (String i:w0)
		     res+=i.toString();

		for (String i:w1)
		     res+=i.toString();
		for (String i:w2)
		     res+=i.toString();
		for (String i:w3)
		     res+=i.toString();
		
		return res;
	}
	
	public static String MixColumns(String state){
		//wikipedia: a mixing operation which operates on the columns of the state, combining the four bytes in each column
		int y=0;
		 int b[]= new int[16];
		 for(int ii=0; ii<32; ii+=2){
			 b[y]= Integer.parseUnsignedInt(state.substring(ii,ii+2), 16);
			 y++;
		 }
		String res="";
		//Note: Mask 0xFF to make unsigned
		//column 1
		String d10 = String.format("%02X",((hbit(b[0]))^((hbit(b[4])^b[4]))^(b[8])^(b[12]))&0xFF);
		String d11 = String.format("%02X",((hbit(b[1]))^((hbit(b[5])^b[5]))^(b[9])^(b[13]))&0xFF);
		String d12 = String.format("%02X",((hbit(b[2]))^((hbit(b[6])^b[6]))^(b[10])^(b[14]))&0xFF);
		String d13 = String.format("%02X",((hbit(b[3]))^((hbit(b[7])^b[7]))^(b[11])^(b[15]))&0xFF);
		
		//second column
		String d20 = String.format("%02X",((b[0])^(hbit(b[4]))^(hbit(b[8])^b[8])^(b[12]))&0xFF);
		String d21 = String.format("%02X",((b[1])^(hbit(b[5]))^(hbit(b[9])^b[9])^(b[13]))&0xFF);
		String d22 = String.format("%02X",((b[2])^(hbit(b[6]))^(hbit(b[10])^b[10])^(b[14]))&0xFF);
		String d23 = String.format("%02X",((b[3])^(hbit(b[7]))^(hbit(b[11])^b[11])^(b[15]))&0xFF);

		//third column 
		String d30 = String.format("%02X",((b[0])^((b[4]))^(hbit(b[8]))^(hbit(b[12])^b[12]))&0xFF);
		String d31 = String.format("%02X",((b[1])^((b[5]))^(hbit(b[9]))^(hbit(b[13])^b[13]))&0xFF);
		String d32 = String.format("%02X",((b[2])^((b[6]))^(hbit(b[10]))^(hbit(b[14])^b[14]))&0xFF);
		String d33 = String.format("%02X",((b[3])^((b[7]))^(hbit(b[11]))^(hbit(b[15])^b[15]))&0xFF);
		
		//fourth column
		String d40 = String.format("%02X",((hbit(b[0])^b[0])^b[4]^b[8]^hbit(b[12]))&0xFF);
		String d41 = String.format("%02X",((hbit(b[1])^b[1])^b[5]^b[9]^hbit(b[13]))&0xFF);
		String d42 = String.format("%02X",((hbit(b[2])^b[2])^b[6]^b[10]^hbit(b[14]))&0xFF);
		String d43 = String.format("%02X",((hbit(b[3])^b[3])^b[7]^b[11]^hbit(b[15]))&0xFF);
	
		//put results in string to fill matrix
		res+=d10;
		res+=d20;
		res+=d30;
		res+=d40;
		
		res+=d11;
		res+=d21;
		res+=d31;
		res+=d41;
		
		res+=d12;
		res+=d22;
		res+=d32;
		res+=d42;
		
		res+=d13;
		res+=d23;
		res+=d33;
		res+=d43;
		return res;
	}
	
	
	public static String addroundkey(String key, String state){
		//"Wikipedia: each byte of the state is combined with a block of the round key using bitwise xor."
		//Note: key string will be changed to be by column
		String keymat = "";
		String smat="";
		String res="";
		//for key
		 for(int ii=0; ii<32; ii+=8)//first column
			 keymat+=key.substring(ii,ii+2);
		 for(int ii=2; ii<32; ii+=8)//second column
			 keymat+=key.substring(ii,ii+2);
		 for(int ii=4; ii<32; ii+=8)//third column
			 keymat+=key.substring(ii,ii+2);
		 for(int ii=6; ii<32; ii+=8)//fourth column
			 keymat+=key.substring(ii,ii+2);

		 //for string 
		 for(int ii=0; ii<32; ii+=8)//first column
			 smat+=state.substring(ii,ii+2);
		 for(int ii=2; ii<32; ii+=8)//second column
			 smat+=state.substring(ii,ii+2);
		 for(int ii=4; ii<32; ii+=8)//third column
			 smat+=state.substring(ii,ii+2);
		 for(int ii=6; ii<32; ii+=8)//fourth column
			 smat+=state.substring(ii,ii+2);

		 for(int ii=0; ii<31;ii+=2){
			  BigInteger i1 = new BigInteger(smat.substring(ii, ii+2), 16);
			  BigInteger i2 = new BigInteger(keymat.substring(ii, ii+2), 16);
			  BigInteger r = i1.xor(i2);
			  String s = String.format("%02X",r);
			  res += s;
		}
		// System.out.println(res);
		return res;
	}
	
	public static String makekeys(String key, int roundcnt){
		ArrayList<String> w0 = new ArrayList<String>();
		ArrayList<String> w1 = new ArrayList<String>();
		ArrayList<String> w2 = new ArrayList<String>();
		ArrayList<String> w3 = new ArrayList<String>();
		ArrayList<String> gw3 = new ArrayList<String>();
		ArrayList<String> w4 = new ArrayList<String>();
		ArrayList<String> w5 = new ArrayList<String>();
		ArrayList<String> w6 = new ArrayList<String>();
		ArrayList<String> w7 = new ArrayList<String>();
		
		for(int j=0; j<8;j+=2){
			w0.add(key.substring(j, j+2));
		}

		for(int j=8; j<16;j+=2){
			w1.add(key.substring(j, j+2));  
		}
		
		for(int j=16; j<24;j+=2){
			w2.add(key.substring(j, j+2));
		}
		
		for(int j=24; j<32;j+=2){
			w3.add(key.substring(j, j+2));
		}
		
		for(int j=24; j<32;j+=2){
			gw3.add(key.substring(j, j+2));
		}
	    
		//1.circular byte left shift on w3
		String temp = gw3.get(0);
		gw3.remove(0);
		gw3.add(temp);

		//2.Byte Substitution with S-Box
		for(int i1=0; i1<4;i1++){
			int tmp =sbox[Integer.parseInt(gw3.get(i1),16)];
			gw3.remove(i1);//remove current element at index
			gw3.add(i1, String.format("%02X", tmp));//add to index and shift other elements			
		}
		

		//3.Add Round Constant (to the first index only)
			int tep = Integer.parseInt(gw3.get(0),16)^(int)(rcon[roundcnt-1]);
			gw3.remove(0);//remove current element at index
			gw3.add(0, String.format("%02X", tep));//add to index and shift other elements
			

			
		//4.XOR operations 
			for(int ii=0; ii<4;ii++){
				//w4=w0^gw3
				int t1 = Integer.parseInt(w0.get(ii),16)^Integer.parseInt(gw3.get(ii),16);
				w4.add(ii, String.format("%02X", t1));//add to index and shift other elements
			
				//w5=w4^w1
				int t2 = Integer.parseInt(w4.get(ii),16)^Integer.parseInt(w1.get(ii),16);
				w5.add(ii, String.format("%02X", t2));//add to index and shift other elements
				
				//w6=w5^w2
				int t3 = Integer.parseInt(w5.get(ii),16)^Integer.parseInt(w2.get(ii),16);
				w6.add(ii, String.format("%02X", t3));//add to index and shift other elements
				
				
				//w7=w6^w3
				int t4 = Integer.parseInt(w6.get(ii),16)^Integer.parseInt(w3.get(ii),16);
				w7.add(ii, String.format("%02X", t4));//add to index and shift other elements
			}
		
		//5.Return round's roundkey
			String res = "";
			for (String i:w4)
			     res+=i.toString();

			for (String i:w5)
			     res+=i.toString();
			for (String i:w6)
			     res+=i.toString();
			for (String i:w7)
			     res+=i.toString();

			return res;
	}//ends makekeys
	
	
	public static int hbit(int a){
		//Do a left shift
		int c = a <<1;
		
		if((a & 0x80) == 0x80)//check if high bit is 1 or not
			c=c^0x1b;			
		return c;
	}
	public static String ciphermake(String s){
		 String rs="";
		 for(int ii=0; ii<32; ii+=8)//first column
			 rs+=s.substring(ii,ii+2);
		 for(int ii=2; ii<32; ii+=8)//second column
			 rs+=s.substring(ii,ii+2);
		 for(int ii=4; ii<32; ii+=8)//third column
			 rs+=s.substring(ii,ii+2);
		 for(int ii=6; ii<32; ii+=8)//fourth column
			 rs+=s.substring(ii,ii+2);
		return rs;
	}
	public static String shelp(String s){
		String rs="";
		for(int ii=0; ii<32; ii+=8)//first column
			 rs+=s.substring(ii,ii+2);
		 for(int ii=2; ii<32; ii+=8)//second column
			 rs+=s.substring(ii,ii+2);
		 for(int ii=4; ii<32; ii+=8)//third column
			 rs+=s.substring(ii,ii+2);
		 for(int ii=6; ii<32; ii+=8)//fourth column
			 rs+=s.substring(ii,ii+2);
		
		return rs;
	}
}//ends class


