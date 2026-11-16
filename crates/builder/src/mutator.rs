//! Binary-level uniqueness mutations applied after compilation.
//!
//! These don't change behaviour — they change the byte signature of the output.

use anyhow::Result;
use rand::RngCore;

pub struct Mutator;

impl Mutator {
    /// Append a random-length, random-content blob after the PE.
    /// Combined with per-build XOR key this ensures every output has a unique hash.
    pub fn append_random_padding(path: &str) -> Result<()> {
        use std::io::Write;
        use rand::Rng;

        let mut rng  = rand::thread_rng();
        let size: usize = rng.gen_range(64..512);
        let mut pad  = vec![0u8; size];
        rng.fill_bytes(&mut pad);

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(path)?;
        file.write_all(&pad)?;

        println!("[*] Appended {} bytes of random padding", size);
        Ok(())
    }

    /// Randomise PE timestamps in-place (compile timestamp at offset 0x108 from PE header).
    pub fn randomise_pe_timestamp(path: &str) -> Result<()> {
        use rand::Rng;

        let mut bytes = std::fs::read(path)?;
        if bytes.len() < 0x40 { return Ok(()); }

        // DOS header e_lfanew at offset 0x3C
        let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into()?) as usize;
        // TimeDateStamp is at PE header offset +0x08
        let ts_off = e_lfanew + 8;
        if bytes.len() < ts_off + 4 { return Ok(()); }

        let fake_ts: u32 = rand::thread_rng().gen_range(0x3000_0000..0x6000_0000);
        bytes[ts_off..ts_off + 4].copy_from_slice(&fake_ts.to_le_bytes());
        std::fs::write(path, &bytes)?;

        println!("[*] PE timestamp randomised → 0x{fake_ts:08X}");
        Ok(())
    }
}
