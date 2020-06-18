use std::i64;
use std::str;
extern crate num_bigint;
use num_bigint::BigUint;

// Rijndael Substitution Box
const sbox: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// Round constant
const rcon: [i64; 11] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
];

fn main() {}

pub struct AES {
    key: String,
    plaintext: String,
    states: Vec<String>,
    cipher: String,
}

impl AES {
    /// Initialize `AES`
    fn new(key: String, plaintext: String) -> Self {
        Self {
            key,
            plaintext,
            states: Vec::new(),
            cipher: String::new(),
        }
    }

    /// Right-pad message (if needed)
    fn padding(&self) {
        let mut i = 0;

        let padding_modulo = self.plaintext.len() % 32;

        if padding_modulo != 0 {
            let pad_scale = 32 - padding_modulo;

            while i < pad_scale {
                self.plaintext += "0";
                i += 1;
            }
        }
    }

    /// Chunk the plaintext into "states"
    fn create_states(&self) {
        self.states = self
            .plaintext
            .as_bytes()
            .chunks(32)
            .map(str::from_utf8)
            .filter_map(Result::ok)
            .map(|s| s.to_string())
            .collect();
    }

    fn update_state(&self, new_state: String, index: usize) {
        self.states[index] = new_state;
    }

    fn update_cipher(&self, s: String) {
        let mut rs = String::new();

        for ii in &[0, 8, 16, 24] {
            //first column
            rs += &s[*ii..*ii + 2];
        }

        for ii in &[2, 10, 18, 26] {
            //second column
            rs += &s[*ii..*ii + 2];
        }

        for ii in &[4, 12, 20, 28] {
            //third column
            rs += &s[*ii..*ii + 2];
        }

        for ii in &[6, 14, 22, 30] {
            //fourth column
            rs += &s[*ii..*ii + 2];
        }

        self.cipher = rs;
    }

    /// Performs AES-128. Returns updated cipher.
    fn execute_aes(&self) -> String {
        self.padding();
        self.create_states();

        // Loop over states
        for ind in 0..self.states.len() {
            let mut kw = Vec::with_capacity(11);
            let mut state = self.states[ind];

            /*Step 1: Key expansion (Make the keys for all rounds + 1 more)*/
            kw[0] = self.key;

            for i in 1..11 {
                kw[i] = self.create_keys(kw[i - 1], i);
            }

            //Step 2 : Initial Round
            self.update_state(self.addroundkey(kw[0], state), ind);

            //Step 3 : Rounds
            for i in 1..10 {
                self.update_state(self.SubBytes(state), ind);
                self.update_state(self.ShiftRows(state), ind);
                self.update_state(self.MixColumns(state), ind);
                self.update_state(self.addroundkey(kw[i], state), ind);
            }

            //Step 4:Final Round(no Mix Columns)
            self.update_state(self.SubBytes(state), ind);
            self.update_state(self.ShiftRows(state), ind);

            // read string by each column instead of across rows (TODO: Check if I need shelp)
            self.update_state(shelp(state), ind);
            self.update_state(self.addroundkey(kw[10], state), ind);

            //cipher text added to by columns
            self.update_cipher(state);
        }

        self.cipher
    }
    /// Replace each byte with another according to a substitution box
    fn SubBytes(&self, state: String) -> String {
        let mut res = String::new();
        let mut w0 = Vec::new(); // 1st row
        let mut w1 = Vec::new(); // 2nd row
        let mut w2 = Vec::new(); // 3rd row
        let mut w3 = Vec::new(); // 4th row

        for j in &[0, 2, 4, 6] {
            w0.push(state[*j..*j + 2].to_string());
        }

        for j in &[8, 10, 12, 14] {
            w1.push(state[*j..*j + 2].to_string());
        }

        for j in &[16, 18, 20, 22] {
            w2.push(state[*j..*j + 2].to_string());
        }

        for j in &[24, 26, 28, 30] {
            w3.push(state[*j..*j + 2].to_string());
        }

        for i1 in 0..4 {
            let tmp = sbox[i64::from_str_radix(&w0.get_mut(i1).unwrap(), 16).unwrap()];
            w0.remove(i1); //remove current element at index
            w0.insert(i1, format!("{:02X}", tmp)); //add to index and shift other elements
        }
        for i1 in 0..4 {
            let tmp = sbox[i64::from_str_radix(&w1.get_mut(i1).unwrap(), 16).unwrap()];
            w1.remove(i1); //remove current element at index
            w1.insert(i1, format!("{:02X}", tmp)); //add to index and shift other elements
        }
        for i1 in 0..4 {
            let tmp = sbox[i64::from_str_radix(&w2.get_mut(i1).unwrap(), 16).unwrap()];
            w2.remove(i1); //remove current element at index
            w2.insert(i1, format!("{:02X}", tmp)); //add to index and shift other elements
        }
        for i1 in 0..4 {
            let tmp = sbox[i64::from_str_radix(&w3.get_mut(i1).unwrap(), 16).unwrap()];
            w3.remove(i1); //remove current element at index
            w3.insert(i1, format!("{:02X}", tmp)); //add to index and shift other elements
        }

        for i in &w0 {
            res += &i;
        }
        for i in &w1 {
            res += &i;
        }
        for i in &w2 {
            res += &i;
        }
        for i in &w3 {
            res += &i;
        }

        res
    }

    fn ShiftRows(&self, state: String) -> String {
        //wikipedia: last three state rows of the state are shifted cyclically by 1, 2, and 3
        let mut res = String::new();
        let mut w0 = Vec::new(); //1st row
        let mut w1 = Vec::new(); //2nd row
        let mut w2 = Vec::new(); //3rd row
        let mut w3 = Vec::new(); //4th row

        for j in &[0, 2, 4, 6] {
            w0.push(&state[*j..*j + 2]);
        }

        for j in &[8, 10, 12, 14] {
            w1.push(&state[*j..*j + 2]);
        }

        for j in &[16, 18, 20, 22] {
            w2.push(&state[*j..*j + 2]);
        }

        for j in &[24, 26, 28, 30] {
            w3.push(&state[*j..*j + 2]);
        }

        //First row is untouched
        //Second row is shifted cyclically to the left
        let mut temp = w1.get_mut(0).unwrap();
        w1.remove(0);
        w1.push(temp);
        //Third row is shifted cyclically to the left 2 times
        let mut temp2 = w2.get_mut(0).unwrap();
        w2.remove(0);
        w2.push(temp2); //now shifted once
        let mut temp3 = w2.get_mut(0).unwrap();
        w2.remove(0);
        w2.push(temp3); //now shifted twice
                        //Third row is shifted cyclically to the left 2 times
        let mut temp4 = w3.get_mut(0).unwrap();
        w3.remove(0);
        w3.push(temp4); //now shifted once
        let mut temp5 = w3.get_mut(0).unwrap();
        w3.remove(0);
        w3.push(temp5); //now shifted twice
        let mut temp6 = w3.get_mut(0).unwrap();
        w3.remove(0);
        w3.push(temp6); //now shifted three times

        for i in &w0 {
            res += &i;
        }
        for i in &w1 {
            res += &i;
        }

        for i in &w2 {
            res += &i;
        }
        for i in &w3 {
            res += &i;
        }

        res
    }

    /// Mixing Operation that operates on the columns of the state, combining the four bytes in each column.
    fn MixColumns(&self, state: String) -> String {
        let ii = 0;
        let mut b = Vec::with_capacity(16);

        while ii < 32 {
            b.push(i64::from_str_radix(&state[ii..(ii + 2)], 16).unwrap());
            ii += 2;
        }

        let mut res = String::new();
        //Note: Mask 0xFF to make unsigned
        //column 1

        let d10 = format!(
            "{:02X}",
            ((hbit(b[0])) ^ (hbit(b[4]) ^ b[4]) ^ (b[8]) ^ (b[12])) & 0xFF
        );
        let d11 = format!(
            "{:02X}",
            ((hbit(b[1])) ^ (hbit(b[5]) ^ b[5]) ^ (b[9]) ^ (b[13])) & 0xFF
        );
        let d12 = format!(
            "{:02X}",
            ((hbit(b[2])) ^ (hbit(b[6]) ^ b[6]) ^ (b[10]) ^ (b[14])) & 0xFF
        );
        let d13 = format!(
            "{:02X}",
            ((hbit(b[3])) ^ (hbit(b[7]) ^ b[7]) ^ (b[11]) ^ (b[15])) & 0xFF
        );

        //second column
        let d20 = format!(
            "{:02X}",
            ((b[0]) ^ (hbit(b[4])) ^ (hbit(b[8]) ^ b[8]) ^ (b[12])) & 0xFF
        );
        let d21 = format!(
            "{:02X}",
            ((b[1]) ^ (hbit(b[5])) ^ (hbit(b[9]) ^ b[9]) ^ (b[13])) & 0xFF
        );
        let d22 = format!(
            "{:02X}",
            ((b[2]) ^ (hbit(b[6])) ^ (hbit(b[10]) ^ b[10]) ^ (b[14])) & 0xFF
        );
        let d23 = format!(
            "{:02X}",
            ((b[3]) ^ (hbit(b[7])) ^ (hbit(b[11]) ^ b[11]) ^ (b[15])) & 0xFF
        );

        //third column
        let d30 = format!(
            "{:02X}",
            ((b[0]) ^ (b[4]) ^ (hbit(b[8])) ^ (hbit(b[12]) ^ b[12])) & 0xFF
        );
        let d31 = format!(
            "{:02X}",
            ((b[1]) ^ (b[5]) ^ (hbit(b[9])) ^ (hbit(b[13]) ^ b[13])) & 0xFF
        );
        let d32 = format!(
            "{:02X}",
            ((b[2]) ^ (b[6]) ^ (hbit(b[10])) ^ (hbit(b[14]) ^ b[14])) & 0xFF
        );
        let d33 = format!(
            "{:02X}",
            ((b[3]) ^ (b[7]) ^ (hbit(b[11])) ^ (hbit(b[15]) ^ b[15])) & 0xFF
        );

        //fourth column
        let d40 = format!(
            "{:02X}",
            ((hbit(b[0]) ^ b[0]) ^ b[4] ^ b[8] ^ hbit(b[12])) & 0xFF
        );
        let d41 = format!(
            "{:02X}",
            ((hbit(b[1]) ^ b[1]) ^ b[5] ^ b[9] ^ hbit(b[13])) & 0xFF
        );
        let d42 = format!(
            "{:02X}",
            ((hbit(b[2]) ^ b[2]) ^ b[6] ^ b[10] ^ hbit(b[14])) & 0xFF
        );
        let d43 = format!(
            "{:02X}",
            ((hbit(b[3]) ^ b[3]) ^ b[7] ^ b[11] ^ hbit(b[15])) & 0xFF
        );

        //put results in string to fill matrix
        res += &d10;
        res += &d20;
        res += &d30;
        res += &d40;

        res += &d11;
        res += &d21;
        res += &d31;
        res += &d41;

        res += &d12;
        res += &d22;
        res += &d32;
        res += &d42;

        res += &d13;
        res += &d23;
        res += &d33;
        res += &d43;

        res
    }

    /// Combine each byte of the state with a blokck of the round key using bitwise xor.
    /// Important Note: key string will be changed to be by column
    fn addroundkey(&self, key: String, state: String) -> String {
        let keymat = String::new();
        let smat = String::new();
        let res = String::new();

        //for key
        for ii in &[0, 8, 16, 24] {
            //first column
            keymat += &key[*ii..*ii + 2];
        }
        for ii in &[2, 10, 18, 26] {
            //second column
            keymat += &key[*ii..*ii + 2];
        }
        for ii in &[4, 12, 20, 28] {
            //third column
            keymat += &key[*ii..*ii + 2];
        }
        for ii in &[6, 14, 22, 30] {
            //fourth column
            keymat += &key[*ii..*ii + 2];
        }

        //for string
        for ii in &[0, 8, 16, 24] {
            //first column
            smat += &state[*ii..*ii + 2];
        }
        for ii in &[2, 10, 18, 26] {
            //second column
            smat += &state[*ii..*ii + 2];
        }
        for ii in &[4, 12, 20, 28] {
            //third column
            smat += &state[*ii..*ii + 2];
        }
        for ii in &[6, 14, 22, 30] {
            //fourth column
            smat += &state[*ii..*ii + 2];
        }

        for ii in &[0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30] {
            let i1 = BigUint::parse_bytes(&smat[*ii..*ii + 2].as_bytes(), 16).unwrap();
            let i2 = BigUint::parse_bytes(&keymat[*ii..*ii + 2].as_bytes(), 16).unwrap();
            res += &format!("{:02X}", i1 ^ i2);
        }
        // println!("res: {}", res);
        res
    }

    fn create_keys(&self, key: String, roundcnt: usize) -> String {
        let mut w0: Vec<String> = Vec::with_capacity(4);
        let mut w1: Vec<String> = Vec::with_capacity(4);
        let mut w2: Vec<String> = Vec::with_capacity(4);
        let mut w3: Vec<String> = Vec::with_capacity(4);
        let mut gw3: Vec<String> = Vec::with_capacity(4);
        let mut w4: Vec<String> = Vec::with_capacity(4);
        let mut w5: Vec<String> = Vec::with_capacity(4);
        let mut w6: Vec<String> = Vec::with_capacity(4);
        let mut w7: Vec<String> = Vec::with_capacity(4);

        for j in &[0, 2, 4, 6] {
            w0.push(key[*j..*j + 2].to_string());
        }

        for j in &[8, 10, 12, 14] {
            w1.push(key[*j..*j + 2].to_string());
        }

        for j in &[16, 18, 20, 22] {
            w2.push(key[*j..*j + 2].to_string());
        }

        for j in &[24, 26, 28, 30] {
            w3.push(key[*j..*j + 2].to_string());
            gw3.push(key[*j..*j + 2].to_string());
        }

        //1.circular byte left shift on w3
        let mut temp = gw3.get_mut(0).unwrap();
        gw3.remove(0);
        gw3.push(temp.to_string());

        //2.Byte Substitution with S-Box
        for i1 in 0..4 {
            let tmp = sbox[i64::from_str_radix(gw3.get_mut(i1).unwrap().as_ref(), 16).unwrap()];
            gw3.remove(i1); //remove current element at index
            gw3.insert(i1, format!("{:02X}", tmp)); //add to index and shift other elements
        }

        //3.Add Round Constant (to the first index only)
        let tep = i64::from_str_radix(gw3.get_mut(0).unwrap().as_ref(), 16).unwrap()
            ^ (rcon[roundcnt - 1]);
        gw3.remove(0); //remove current element at index
        gw3.insert(0, format!("{:02X}", tep)); //add to index and shift other elements

        //4.XOR operations
        for ii in 0..4 {
            //w4=w0^gw3
            let t1 = i64::from_str_radix(w0.get_mut(ii).unwrap().as_ref(), 16).unwrap()
                ^ i64::from_str_radix(gw3.get_mut(ii).unwrap().as_ref(), 16).unwrap();
            w4.insert(ii, format!("{:02X}", t1)); //add to index and shift other elements

            //w5=w4^w1
            let t2 = i64::from_str_radix(w4.get_mut(ii).unwrap().as_ref(), 16).unwrap()
                ^ i64::from_str_radix(w1.get_mut(ii).unwrap().as_ref(), 16).unwrap();
            w5.insert(ii, format!("{:02X}", t2)); //add to index and shift other elements

            //w6=w5^w2
            let t3 = i64::from_str_radix(w5.get_mut(ii).unwrap().as_ref(), 16).unwrap()
                ^ i64::from_str_radix(w2.get_mut(ii).unwrap().as_ref(), 16).unwrap();
            w6.insert(ii, format!("{:02X}", t3)); //add to index and shift other elements

            //w7=w6^w3
            let t4 = i64::from_str_radix(w6.get_mut(ii).unwrap().as_ref(), 16).unwrap()
                ^ i64::from_str_radix(w3.get_mut(ii).unwrap().as_ref(), 16).unwrap();
            w7.insert(ii, format!("{:02X}", t4)); //add to index and shift other elements
        }

        //5.Return round's roundkey
        let mut res = String::new();
        for i in &w4 {
            res += &i;
        }
        for i in &w5 {
            res += &i;
        }
        for i in &w6 {
            res += &i;
        }
        for i in &w7 {
            res += &i;
        }

        res
    }
}

// ################################### Helper functions ###################################
pub fn hbit(a: i64) -> i64 {
    //Do a left shift
    let c = a << 1;

    //check if high bit is 1 or not
    if (a & 0x80) == 0x80 {
        c = c ^ 0x1b;
    }

    c
}

pub fn shelp(s: String) -> String {
    let mut rs = String::new();
    for ii in &[0, 8, 16, 24] {
        //first column
        rs += &s[*ii..*ii + 2];
    }

    for ii in &[2, 10, 18, 26] {
        //second column
        rs += &s[*ii..*ii + 2];
    }

    for ii in &[4, 12, 20, 28] {
        //third column
        rs += &s[*ii..*ii + 2];
    }

    for ii in &[6, 14, 22, 30] {
        //fourth column
        rs += &s[*ii..*ii + 2];
    }

    rs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example1() {
        let key = "5468617473206D79204B756E67204675".to_string(); //128-bit key (in hexadecimal)
        let plaintext = "544F4E20776E69546F656E772020656F".to_string(); // in hexadecimal

        println!("Example 1:");
        println!("Key: {}", key);
        println!("Plaintext: {}", plaintext);
        let cipher = AES::new(key, plaintext).execute_aes();
        println!("Ciphertext: {}", cipher);
        let expected_ciphertext = "9A1AF35C9823EE1CC888A1C8090460B2";
        assert_eq!(expected_ciphertext, cipher);
    }

    #[test]
    fn example2() {
        // Source: Textbook Ch.5.5 (p.169)
        let key = "0f1571c947d9e8590cb7add6af7f6798".to_string(); //128-bit key (in hexadecimal)
        let plaintext = "0123456789abcdeffedcba9876543210".to_string(); // in hexadecimal

        println!("Example 2:");
        println!("Key: {}", key);
        println!("Plaintext: {}", plaintext);
        let cipher = AES::new(key, plaintext).execute_aes();
        println!("Ciphertext: {}", cipher);
        let expected_ciphertext = "FF0B844A0853BF7C6934AB4364148FB9";
        assert_eq!(expected_ciphertext, cipher);
    }
}
