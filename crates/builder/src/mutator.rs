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

    /// Zero out the Rich Header (the undocumented Microsoft linker fingerprint).
    ///
    /// Rich header sits between the DOS stub and the PE header.  It ends with
    /// the 4-byte magic "Rich" followed by a 4-byte XOR key.  Walk backward
    /// from e_lfanew to find it, then overwrite the whole block with zeros.
    pub fn zero_rich_header(path: &str) -> Result<()> {
        let mut bytes = std::fs::read(path)?;
        if bytes.len() < 0x40 { return Ok(()); }

        let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into()?) as usize;
        if e_lfanew < 8 || e_lfanew > bytes.len() { return Ok(()); }

        // Search backward for "Rich" magic (0x52 0x69 0x63 0x68)
        let region = &bytes[0x40..e_lfanew];
        if let Some(rel) = region.windows(4).rposition(|w| w == b"Rich") {
            let rich_off = 0x40 + rel;
            // Overwrite from start of DOS stub padding (offset 0x40) through
            // the "Rich" + xor-key footer (8 bytes).
            for b in &mut bytes[0x40..rich_off + 8] {
                *b = 0;
            }
            std::fs::write(path, &bytes)?;
            println!("[*] Rich header zeroed ({} bytes)", rich_off + 8 - 0x40);
        }
        Ok(())
    }

    /// Randomise the names of PE section headers in-place.
    ///
    /// Each section name is an 8-byte null-padded field in the section table,
    /// starting at e_lfanew + 4 (PE sig) + 20 (COFF header) + SizeOfOptionalHeader.
    pub fn randomise_section_names(path: &str) -> Result<()> {
        use rand::Rng;

        const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng   = rand::thread_rng();
        let mut bytes = std::fs::read(path)?;
        if bytes.len() < 0x40 { return Ok(()); }

        let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into()?) as usize;
        // PE signature (4) + COFF header (20) = 24 bytes
        // SizeOfOptionalHeader is at COFF+16
        if e_lfanew + 24 > bytes.len() { return Ok(()); }
        let opt_hdr_size = u16::from_le_bytes(
            bytes[e_lfanew + 20..e_lfanew + 22].try_into()?
        ) as usize;
        let num_sections = u16::from_le_bytes(
            bytes[e_lfanew + 6..e_lfanew + 8].try_into()?
        ) as usize;

        let section_table_off = e_lfanew + 24 + opt_hdr_size;
        for i in 0..num_sections {
            let name_off = section_table_off + i * 40;
            if name_off + 8 > bytes.len() { break; }
            let name_len: usize = rng.gen_range(4..=7);
            let mut name = [0u8; 8];
            name[0] = b'.';
            for j in 1..name_len {
                name[j] = CHARS[rng.gen_range(0..CHARS.len())];
            }
            bytes[name_off..name_off + 8].copy_from_slice(&name);
        }

        std::fs::write(path, &bytes)?;
        println!("[*] Section names randomised ({num_sections} sections)");
        Ok(())
    }
}
