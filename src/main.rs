use std::i64;
use std::str;
extern crate num_bigint;
use num_bigint::BigUint;

fn main() {}

pub struct AES {
    key: String,
    plaintext: String,
    states: Vec<String>,
    cipher: String,
}

impl AES {
    /// Initialize `AES`
    fn new(key: String, plaintext: String) {
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

        let padding_modulo = plaintext.length() % 32;

        if padding_modulo != 0 {
            let pad_scale = 32 - padding_modulo;

            while (i < pad_scale) {
                self.plaintext += "0";
                i += 1;
            }
        }
    }

    /// Chunk the plaintext into "states"
    fn create_states(&self) {
        self.states = self
            .plaintext
            .chunks(32)
            .map(str::from_utf8)
            .collect::<Result<Vec<&str>, _>>()
            .unwrap();
    }

    fn update_state(&self, new_state: String, index: u8) {
        self.states[index] = new_state;
    }

    fn update_cipher(s: String) {
        let mut rs = String::new();

        for ii in &[0, 8, 16, 24] {
            //first column
            rs += s[ii..ii + 2];
        }

        for ii in &[2, 10, 18, 26] {
            //second column
            rs += s[ii..ii + 2];
        }

        for ii in &[4, 12, 20, 28] {
            //third column
            rs += s[ii..ii + 2];
        }

        for ii in &[6, 14, 22, 30] {
            //fourth column
            rs += s[ii..ii + 2];
        }

        self.cipher = rs;
    }

    /// Performs AES-128. Returns updated cipher.
    fn execute_aes(&self) -> String {
        self.padding();
        self.create_states();

        // Loop over states
        for ind in 0..len(self.states) {
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
            update_cipher(state);
        }

        return self.cipher;
    }
    /// Replace each byte with another according to a substitution box
    fn SubBytes(state: String) -> String {
        let mut res = String::new();
        let mut w0 = Vec::new(); // 1st row
        let mut w1 = Vec::new(); // 2nd row
        let mut w2 = Vec::new(); // 3rd row
        let mut w3 = Vec::new(); // 4th row

        for j in &[0, 2, 4, 6] {
            w0.append(state[j..j + 2]);
        }

        for j in &[8, 10, 12, 14] {
            w1.append(state[j..j + 2]);
        }

        for j in &[16, 18, 20, 22] {
            w2.append(state[j..j + 2]);
        }

        for j in &[24, 26, 28, 30] {
            w3.append(state[j..j + 2]);
        }

        for i1 in 0..4 {
            let tmp = sbox[i64::from_str_radix(w0.get(i1), 16).unwrap()];
            w0.remove(i1); //remove current element at index
            w0.append(i1, format!("{:02X}", tmp)); //add to index and shift other elements
        }
        for i1 in 0..4 {
            let tmp = sbox[i64::from_str_radix(w1.get(i1), 16).unwrap()];
            w1.remove(i1); //remove current element at index
            w1.append(i1, format!("{:02X}", tmp)); //add to index and shift other elements
        }
        for i1 in 0..4 {
            let tmp = sbox[i64::from_str_radix(w2.get(i1), 16).unwrap()];
            w2.remove(i1); //remove current element at index
            w2.append(i1, format!("{:02X}", tmp)); //add to index and shift other elements
        }
        for i1 in 0..4 {
            let tmp = sbox[i64::from_str_radix(w3.get(i1), 16).unwrap()];
            w3.remove(i1); //remove current element at index
            w3.append(i1, format!("{:02X}", tmp)); //add to index and shift other elements
        }

        for i in w0 {
            res += i;
        }
        for i in w1 {
            res += i;
        }
        for i in w2 {
            res += i;
        }
        for i in w3 {
            res += i;
        }
        return res;
    }

    fn ShiftRows(state: String) -> String {
        //wikipedia: last three state rows of the state are shifted cyclically by 1, 2, and 3
        let mut res = String::new();
        let mut w0 = Vec::new(); //1st row
        let mut w1 = Vec::new(); //2nd row
        let mut w2 = Vec::new(); //3rd row
        let mut w3 = Vec::new(); //4th row

        for j in &[0, 2, 4, 6] {
            w0.append(state[j..j + 2]);
        }

        for j in &[8, 10, 12, 14] {
            w1.append(state[j..j + 2]);
        }

        for j in &[16, 18, 20, 22] {
            w2.append(state[j..j + 2]);
        }

        for j in &[24, 26, 28, 30] {
            w3.append(state[j..j + 2]);
        }

        //First row is untouched
        //Second row is shifted cyclically to the left
        let temp = w1.get(0);
        w1.remove(0);
        w1.append(temp);
        //Third row is shifted cyclically to the left 2 times
        let temp2 = w2.get(0);
        w2.remove(0);
        w2.append(temp2); //now shifted once
        let temp3 = w2.get(0);
        w2.remove(0);
        w2.append(temp3); //now shifted twice
                          //Third row is shifted cyclically to the left 2 times
        let temp4 = w3.get(0);
        w3.remove(0);
        w3.append(temp4); //now shifted once
        let temp5 = w3.get(0);
        w3.remove(0);
        w3.append(temp5); //now shifted twice
        let temp6 = w3.get(0);
        w3.remove(0);
        w3.append(temp6); //now shifted three times

        for i in w0 {
            res += i;
        }
        for i in w1 {
            res += i;
        }

        for i in w2 {
            res += i;
        }
        for i in w3 {
            res += i;
        }

        return res;
    }

    /// Mixing Operation that operates on the columns of the state, combining the four bytes in each column.
    fn MixColumns(state: String) -> String {
        let ii = 0;
        let mut b = Vec::with_capacity(16);

        while ii < 32 {
            b.push(i64::from_str_radix(&state[ii..ii + 2], 16).unwrap());
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
        res += d10;
        res += d20;
        res += d30;
        res += d40;

        res += d11;
        res += d21;
        res += d31;
        res += d41;

        res += d12;
        res += d22;
        res += d32;
        res += d42;

        res += d13;
        res += d23;
        res += d33;
        res += d43;
        return res;
    }

    /// Combine each byte of the state with a blokck of the round key using bitwise xor.
    /// Important Note: key string will be changed to be by column
    fn addroundkey(key: String, state: String) -> String {
        let keymat = String::new();
        let smat = String::new();
        let res = String::new();

        //for key
        for ii in &[0, 8, 16, 24] {
            //first column
            keymat += key[ii..ii + 2];
        }
        for ii in &[2, 10, 18, 26] {
            //second column
            keymat += key[ii..ii + 2];
        }
        for ii in &[4, 12, 20, 28] {
            //third column
            keymat += key[ii..ii + 2];
        }
        for ii in &[6, 14, 22, 30] {
            //fourth column
            keymat += key[ii..ii + 2];
        }

        //for string
        for ii in &[0, 8, 16, 24] {
            //first column
            smat += state[ii..ii + 2];
        }
        for ii in &[2, 10, 18, 26] {
            //second column
            smat += state[ii..ii + 2];
        }
        for ii in &[4, 12, 20, 28] {
            //third column
            smat += state[ii..ii + 2];
        }
        for ii in &[6, 14, 22, 30] {
            //fourth column
            smat += state[ii..ii + 2];
        }

        for ii in &[0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30] {
            let i1 = BigUint::parse_bytes(smat[ii..ii + 2].as_bytes(), 16);
            let i2 = BigUint::parse_bytes(keymat[ii..ii + 2].as_bytes(), 16);
            res += format!("{:02X}", i1 ^ i2);
        }
        // println!("res: {}", res);
        return res;
    }

    fn create_keys(key: String, roundcnt: u8) -> String {
        let mut w0 = Vec::new();
        let mut w1 = Vec::new();
        let mut w2 = Vec::new();
        let mut w3 = Vec::new();
        let mut gw3 = Vec::new();
        let mut w4 = Vec::new();
        let mut w5 = Vec::new();
        let mut w6 = Vec::new();
        let mut w7 = Vec::new();

        for j in &[0, 2, 4, 6] {
            w0.append(state[j..j + 2]);
        }

        for j in &[8, 10, 12, 14] {
            w1.append(state[j..j + 2]);
        }

        for j in &[16, 18, 20, 22] {
            w2.append(state[j..j + 2]);
        }

        for j in &[24, 26, 28, 30] {
            w3.append(key[j..j + 2]);
            gw3.append(state[j..j + 2]);
        }

        //1.circular byte left shift on w3
        lettemp = gw3.get(0);
        gw3.remove(0);
        gw3.append(temp);

        //2.Byte Substitution with S-Box
        for i1 in 0..4 {
            let tmp = sbox[i64::from_str_radix(gw3.get(i1), 16).unwrap()];
            gw3.remove(i1); //remove current element at index
            gw3.append(i1, format!("{:02X}", tmp)); //add to index and shift other elements
        }

        //3.Add Round Constant (to the first index only)
        let tep = i64::from_str_radix(gw3.get(0), 16).unwrap() ^ (rcon[roundcnt - 1]);
        gw3.remove(0); //remove current element at index
        gw3.append(0, format!("{:02X}", tep)); //add to index and shift other elements

        //4.XOR operations
        for ii in 0..4 {
            //w4=w0^gw3
            let t1 = i64::from_str_radix(w0.get(ii), 16).unwrap()
                ^ i64::from_str_radix(gw3.get(ii), 16).unwrap();
            w4.append(ii, format!("{:02X}", t1)); //add to index and shift other elements

            //w5=w4^w1
            let t2 = i64::from_str_radix(w4.get(ii), 16).unwrap()
                ^ i64::from_str_radix(w1.get(ii), 16).unwrap();
            w5.append(ii, format!("{:02X}", t2)); //add to index and shift other elements

            //w6=w5^w2
            let t3 = i64::from_str_radix(w5.get(ii), 16).unwrap()
                ^ i64::from_str_radix(w2.get(ii), 16).unwrap();
            w6.append(ii, format!("{:02X}", t3)); //add to index and shift other elements

            //w7=w6^w3
            let t4 = i64::from_str_radix(w6.get(ii), 16).unwrap()
                ^ i64::from_str_radix(w3.get(ii), 16).unwrap();
            w7.append(ii, format!("{:02X}", t4)); //add to index and shift other elements
        }

        //5.Return round's roundkey
        let mut res = String::new();
        for i in w4 {
            res += i;
        }
        for i in w5 {
            res += i;
        }
        for i in w6 {
            res += i;
        }
        for i in w7 {
            res += i;
        }

        return res;
    }
}

// ################################### Helper functions ###################################
fn hbit(a: u8) -> u8 {
    //Do a left shift
    let c = a << 1;

    //check if high bit is 1 or not
    if ((a & 0x80) == 0x80) {
        c = c ^ 0x1b;
    }

    return c;
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
        let cipher = AES::new(key, plaintext).execute_aes();
        println!("Ciphertext: {}", cipher);
        let expected_ciphertext = "9A1AF35C9823EE1CC888A1C8090460B2";
        assert_eq!(expected_ciphertext, cipher);
    }

    #[test]
    fn example2() {
        // Source: Textbook Ch.5.5 (p.169)
        let key = "0f1571c947d9e8590cb7add6af7f6798"; //128-bit key (in hexadecimal)
        let plaintext = "0123456789abcdeffedcba9876543210"; // in hexadecimal

        println!("Example 2:");
        println!("Key: {}", key);
        println!("Plaintext: {}", plaintext);
        let cipher = AES::new(key, plaintext).execute_aes();
        println!("Ciphertext: {}", cipher);
        let expected_ciphertext = "FF0B844A0853BF7C6934AB4364148FB9";
        assert_eq!(expected_ciphertext, cipher);
    }
}
