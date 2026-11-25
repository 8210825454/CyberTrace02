use sha2::{Digest, Sha256};
use std::{env, fs::File, io::{BufReader, Read}};
fn main() {
    let path = env::args().nth(1).expect("Usage: cybertrace-parser <evidence-file>");
    let mut reader = BufReader::new(File::open(&path).expect("Cannot open evidence file"));
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    let mut bytes = 0u64;
    loop {
        let n = reader.read(&mut buffer).expect("Read failed");
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
        bytes += n as u64;
    }
    println!("file={}", path);
    println!("bytes={}", bytes);
    println!("sha256={:x}", hasher.finalize());
}