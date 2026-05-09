fn main() {
    let x: u32 = 0xE192468C; // The plaintext
    let key: u32 = 0x536491A3;
    
    // Encrypting: Ror, Sub, Sub, Ror
    let a = x.rotate_right(1);
    let b = a.wrapping_sub(key);
    let c = b.wrapping_sub(key);
    let d = c.rotate_right(1);
    
    println!("Encrypted: {:08X}", d);

    // Let's test the other direction.
    // If the ciphertext was 0x65000000
    let cipher: u32 = 0x65000000;
    
    // Decrypting (trace): Rol, Add, Add, Rol
    let a = cipher.rotate_left(1);
    let b = a.wrapping_add(key);
    let c = b.wrapping_add(key);
    let d = c.rotate_left(1);
    
    println!("Decrypted: {:08X}", d);
}
