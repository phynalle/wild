//! CodeView and PDB encoding from the shared engine's selected objects and final addresses.
use super::backend::Coff;
use crate::args::coff::CoffArgs;
use crate::error::{Context, Result};
use crate::layout::{FileLayout, Layout, ObjectLayout};
use crate::platform::{ObjectFile as _, RelocationSequence as _};
use crate::{bail, ensure};
use rayon::prelude::*;
use std::hash::{BuildHasher, Hasher};
use std::path::Path;
use std::sync::Arc;

pub(super) struct Pdb {
    streams: Vec<Vec<u8>>,
    msf: Msf,
    pub guid: [u8; 16],
    pub path: Arc<Path>,
}

impl Pdb {
    pub(super) fn write<F: crate::FileSystem>(
        &self,
        output: &crate::file_writer::Output<F>,
    ) -> Result {
        crate::timing_phase!("Write PDB MSF");
        output.write_auxiliary_with(&self.path, self.msf.size()? as u64, |bytes| {
            self.msf.write(&self.streams, bytes)
        })
    }
}

#[derive(Debug)]
pub(super) struct Asset<'data> {
    pub name: String,
    pub data: &'data [u8],
}

pub(super) fn output_path(args: &CoffArgs) -> Arc<Path> {
    args.pdb
        .clone()
        .unwrap_or_else(|| Arc::from(args.common.output.with_extension("pdb")))
}

pub(super) fn embedded_path(args: &CoffArgs, absolute: &Path) -> Result<String> {
    let path = output_path(args);
    let file = path
        .file_name()
        .and_then(|s| s.to_str())
        .context("Invalid PDB filename")?;
    let text = if let Some(alt) = &args.pdb_alt_path {
        alt.replace("%_PDB%", file).replace(
            "%_EXT%",
            path.extension()
                .and_then(|s| s.to_str())
                .unwrap_or_default(),
        )
    } else {
        absolute
            .to_str()
            .context("PDB path is not UTF-8")?
            .to_owned()
    };
    ensure!(!text.contains('\0'), "PDB path contains a null byte");
    Ok(text)
}

pub(super) fn directory_object(args: &CoffArgs, absolute: &Path) -> Result<Vec<u8>> {
    use object::write::{Object, Relocation, Symbol, SymbolSection};
    use object::{
        Architecture, BinaryFormat, Endianness, RelocationFlags, SectionKind, SymbolFlags,
        SymbolKind, SymbolScope,
    };
    let mut bytes = vec![0; 28];
    put32(&mut bytes, 12, 2);
    let path = embedded_path(args, absolute)?;
    put32(&mut bytes, 16, u32::try_from(24 + path.len() + 1)?);
    bytes.extend_from_slice(b"RSDS");
    bytes.extend_from_slice(&[0; 16]);
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(path.as_bytes());
    bytes.push(0);
    let mut o = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let section = o.add_section(
        Vec::new(),
        b".rdata$wilddbg".to_vec(),
        SectionKind::ReadOnlyData,
    );
    o.append_section_data(section, &bytes, 4);
    let symbol = o.add_symbol(Symbol {
        name: b"__wild_debug_directory".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(section),
        flags: SymbolFlags::None,
    });
    o.add_relocation(
        section,
        Relocation {
            offset: 20,
            symbol,
            addend: 28,
            flags: RelocationFlags::Coff {
                typ: object::pe::IMAGE_REL_AMD64_ADDR32NB,
            },
        },
    )?;
    Ok(o.write()?)
}

fn read16(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes
            .get(at..at.checked_add(2).context("CodeView offset overflow")?)
            .context("Truncated CodeView u16")?
            .try_into()
            .unwrap(),
    ))
}
fn read32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at.checked_add(4).context("CodeView offset overflow")?)
            .context("Truncated CodeView u32")?
            .try_into()
            .unwrap(),
    ))
}
fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn push16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
fn push32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
fn pad4(bytes: &mut Vec<u8>) {
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
}
fn cstring(bytes: &[u8], at: usize) -> Result<&[u8]> {
    let rest = bytes.get(at..).context("Invalid CodeView string offset")?;
    Ok(&rest[..rest
        .iter()
        .position(|b| *b == 0)
        .context("Unterminated CodeView string")?])
}
fn numeric_length(bytes: &[u8], at: usize) -> Result<usize> {
    let leaf = read16(bytes, at)?;
    let size = if leaf < 0x8000 {
        2
    } else {
        2 + match leaf {
            0x8000 => 1,
            0x8001 | 0x8002 => 2,
            0x8003..=0x8005 => 4,
            0x8006 | 0x8009 | 0x800a => 8,
            0x8007 => 10,
            0x8008 | 0x8017 | 0x8018 => 16,
            _ => bail!("Unsupported CodeView numeric leaf {leaf:#x}"),
        }
    };
    ensure!(
        bytes.get(at..at + size).is_some(),
        "Truncated CodeView numeric leaf"
    );
    Ok(size)
}

fn records(bytes: &[u8]) -> Result<Vec<&[u8]>> {
    let mut result = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let size = usize::from(read16(bytes, at)?) + 2;
        ensure!(size >= 4, "Invalid CodeView record length");
        let record = bytes
            .get(at..at + size)
            .context("Truncated CodeView record")?;
        result.push(record);
        at += size;
    }
    Ok(result)
}

fn type_references(record: &[u8]) -> Result<smallvec::SmallVec<[(usize, bool); 4]>> {
    let kind = read16(record, 2)?;
    let body = &record[4..];
    let minimum = match kind {
        0x1001 | 0x1205 => 6,
        0x1002 => 8,
        0x1008 | 0x1606 => 12,
        0x1009 => 24,
        0x1504 | 0x1505 | 0x1519 => 18,
        0x1503 | 0x1506 => 10,
        0x1507 => 13,
        0x1601 | 0x1602 => 9,
        0x1605 => 5,
        0x1607 => 14,
        0x000a | 0x000e => 2,
        _ => 0,
    };
    ensure!(body.len() >= minimum, "Truncated CodeView type body");
    let mut refs = smallvec::SmallVec::new();
    let mut run = |at: usize, count: usize, id: bool| -> Result {
        ensure!(
            count <= body.len() / 4 && body.get(at..at + count * 4).is_some(),
            "Truncated CodeView type references"
        );
        refs.extend((0..count).map(|i| (4 + at + i * 4, id)));
        Ok(())
    };
    match kind {
        0x1001 | 0x1205 => run(0, 1, false)?,
        0x1002 => {
            run(0, 1, false)?;
            if matches!((read32(body, 4)? >> 5) & 7, 2 | 3) {
                run(8, 1, false)?;
            }
        }
        0x1008 => {
            run(0, 1, false)?;
            run(8, 1, false)?;
        }
        0x1009 => {
            run(0, 3, false)?;
            run(16, 1, false)?;
        }
        0x1201 => run(4, read32(body, 0)? as usize, false)?,
        0x1503 | 0x151d => run(0, 2, false)?,
        0x1504 | 0x1505 | 0x1519 => run(4, 3, false)?,
        0x1506 => run(4, 1, false)?,
        0x1507 => run(4, 2, false)?,
        0x1601 => {
            run(0, 1, true)?;
            run(4, 1, false)?;
        }
        0x1602 => run(0, 2, false)?,
        0x1603 => run(2, read16(body, 0)? as usize, true)?,
        0x1604 => run(4, read32(body, 0)? as usize, true)?,
        0x1605 => run(0, 1, true)?,
        0x1606 => {
            run(0, 1, false)?;
            run(4, 1, true)?;
        }
        0x1607 => run(0, 1, false)?,
        0x000a | 0x000e => {}
        0x1206 => {
            let mut at = 0;
            while at < body.len() {
                if body[at] >= 0xf0 {
                    break;
                }
                run(at + 4, 1, false)?;
                let mode = (read16(body, at)? >> 2) & 7;
                at += if mode == 4 || mode == 6 { 12 } else { 8 };
            }
        }
        0x1203 => {
            let mut at = 0;
            while at < body.len() {
                if body[at] >= 0xf0 {
                    let size = usize::from(body[at] & 15);
                    ensure!(
                        size != 0 && at + size <= body.len(),
                        "Invalid CodeView field padding"
                    );
                    at += size;
                    continue;
                }
                let leaf = read16(body, at)?;
                let size = match leaf {
                    0x1400 => {
                        run(at + 4, 1, false)?;
                        8 + numeric_length(body, at + 8)?
                    }
                    0x1401 | 0x1402 => {
                        run(at + 4, 2, false)?;
                        let n = numeric_length(body, at + 12)?;
                        12 + n + numeric_length(body, at + 12 + n)?
                    }
                    0x1404 | 0x1409 => {
                        run(at + 4, 1, false)?;
                        8
                    }
                    0x1502 => {
                        let n = 4 + numeric_length(body, at + 4)?;
                        n + cstring(body, at + n)?.len() + 1
                    }
                    0x150d => {
                        run(at + 4, 1, false)?;
                        let n = 8 + numeric_length(body, at + 8)?;
                        n + cstring(body, at + n)?.len() + 1
                    }
                    0x150e | 0x150f | 0x1510 => {
                        run(at + 4, 1, false)?;
                        8 + cstring(body, at + 8)?.len() + 1
                    }
                    0x1511 => {
                        run(at + 4, 1, false)?;
                        let mode = (read16(body, at + 2)? >> 2) & 7;
                        let n = if mode == 4 || mode == 6 { 12 } else { 8 };
                        n + cstring(body, at + n)?.len() + 1
                    }
                    _ => bail!("Unsupported CodeView field leaf {leaf:#x}"),
                };
                ensure!(at + size <= body.len(), "Truncated CodeView field");
                at += size;
            }
        }
        _ => bail!("Unsupported CodeView type leaf {kind:#x}"),
    }
    Ok(refs)
}

struct Types<'data> {
    member: bumpalo_herd::Member<'data>,
    tpi: Vec<&'data [u8]>,
    ipi: Vec<&'data [u8]>,
    tpi_map: hashbrown::HashMap<u64, smallvec::SmallVec<[u32; 1]>>,
    ipi_map: hashbrown::HashMap<u64, smallvec::SmallVec<[u32; 1]>>,
}

struct PreparedType<'data> {
    bytes: &'data [u8],
    references: smallvec::SmallVec<[(usize, bool); 4]>,
    hash: u64,
    is_id: bool,
}

fn prepare_types(bytes: &[u8]) -> Result<Vec<PreparedType<'_>>> {
    ensure!(
        read32(bytes, 0)? == 4,
        "Unsupported CodeView type signature"
    );
    let mut prepared: Vec<PreparedType<'_>> = Vec::new();
    for record in records(&bytes[4..])? {
        let mut references = type_references(record)?;
        references.sort_unstable_by_key(|(at, _)| *at);
        let mut hasher = foldhash::fast::FixedState::default().build_hasher();
        let mut start = 0;
        // COFF types form a backward-reference DAG. Hash that graph in parallel per object;
        // stable global merging still compares complete canonical records on every hash hit.
        for &(at, id) in &references {
            hasher.write(&record[start..at]);
            let index = read32(record, at)?;
            if index < 0x1000 {
                hasher.write_u64(u64::from(index));
            } else {
                let target = prepared
                    .get((index - 0x1000) as usize)
                    .context("Forward or invalid CodeView type index")?;
                ensure!(target.is_id == id, "CodeView type/ID reference mismatch");
                hasher.write_u64(target.hash);
            }
            start = at + 4;
        }
        hasher.write(&record[start..]);
        prepared.push(PreparedType {
            bytes: record,
            references,
            hash: hasher.finish(),
            is_id: matches!(read16(record, 2)?, 0x1601..=0x1607),
        });
    }
    Ok(prepared)
}

fn same_type(record: &PreparedType<'_>, canonical: &[u8], map: &[(u32, bool)]) -> bool {
    if record.bytes.len() != canonical.len() {
        return false;
    }
    let mut start = 0;
    for &(at, _) in &record.references {
        if record.bytes[start..at] != canonical[start..at] {
            return false;
        }
        let source = u32::from_le_bytes(record.bytes[at..at + 4].try_into().unwrap());
        let target = if source < 0x1000 {
            source
        } else {
            map[(source - 0x1000) as usize].0
        };
        if canonical[at..at + 4] != target.to_le_bytes() {
            return false;
        }
        start = at + 4;
    }
    record.bytes[start..] == canonical[start..]
}

impl<'data> Types<'data> {
    fn new(herd: &'data bumpalo_herd::Herd) -> Self {
        Self {
            member: herd.get(),
            tpi: Vec::new(),
            ipi: Vec::new(),
            tpi_map: Default::default(),
            ipi_map: Default::default(),
        }
    }
    fn merge(&mut self, prepared: &[PreparedType<'_>]) -> Result<Vec<(u32, bool)>> {
        let mut map = Vec::with_capacity(prepared.len());
        for record in prepared {
            let id = record.is_id;
            let (lookup, out) = if id {
                (&mut self.ipi_map, &mut self.ipi)
            } else {
                (&mut self.tpi_map, &mut self.tpi)
            };
            let existing = lookup.get(&record.hash).and_then(|candidates| {
                candidates
                    .iter()
                    .copied()
                    .find(|index| same_type(record, &out[(index - 0x1000) as usize], &map))
            });
            let index = if let Some(index) = existing {
                index
            } else {
                let index = u32::try_from(out.len())?
                    .checked_add(0x1000)
                    .context("PDB type index overflow")?;
                let bytes = self.member.alloc_slice_copy(record.bytes);
                for &(at, _) in &record.references {
                    let source = read32(&bytes, at)?;
                    if source >= 0x1000 {
                        put32(bytes, at, map[(source - 0x1000) as usize].0);
                    }
                }
                lookup.entry(record.hash).or_default().push(index);
                out.push(bytes);
                index
            };
            map.push((index, id));
        }
        Ok(map)
    }
    fn stream(records: &[&[u8]], hash_stream: u16) -> Result<(Vec<u8>, Vec<u8>)> {
        let bytes = records.iter().try_fold(0usize, |total, record| {
            total
                .checked_add(record.len())
                .context("PDB type stream size overflow")
        })?;
        let mut out = Vec::with_capacity(56 + bytes);
        out.resize(56, 0);
        put32(&mut out, 0, 20040203);
        put32(&mut out, 4, 56);
        put32(&mut out, 8, 0x1000);
        put32(&mut out, 12, 0x1000 + records.len() as u32);
        put32(&mut out, 16, u32::try_from(bytes)?);
        put16(&mut out, 20, hash_stream);
        put16(&mut out, 22, 0xffff);
        put32(&mut out, 24, 4);
        put32(&mut out, 28, 0x3ffff);
        let mut hashes = Vec::with_capacity(records.len() * 4 + bytes.div_ceil(8192) * 8);
        let mut offsets = Vec::new();
        let mut offset = 0u32;
        for (index, record) in records.iter().enumerate() {
            push32(&mut hashes, type_hash(record)? % 0x3ffff);
            if index == 0 || (offset + record.len() as u32) / 8192 > offset / 8192 {
                push32(&mut offsets, 0x1000 + index as u32);
                push32(&mut offsets, offset);
            }
            offset += record.len() as u32;
            out.extend_from_slice(record);
        }
        let hash_len = hashes.len() as u32;
        put32(&mut out, 36, hash_len);
        put32(&mut out, 40, hash_len);
        put32(&mut out, 44, offsets.len() as u32);
        put32(&mut out, 48, hash_len);
        hashes.extend_from_slice(&offsets);
        Ok((out, hashes))
    }
}

fn type_hash(record: &[u8]) -> Result<u32> {
    let kind = read16(record, 2)?;
    if matches!(kind, 0x1504 | 0x1505 | 0x1519 | 0x1506 | 0x1507) {
        let options = read16(record, 6)?;
        let at = match kind {
            0x1506 => 12 + numeric_length(record, 12)?,
            0x1507 => 16,
            _ => 20 + numeric_length(record, 20)?,
        };
        let name = cstring(record, at)?;
        let anonymous = options & 0x200 != 0
            && (name.ends_with(b"<unnamed-tag>") || name.ends_with(b"__unnamed"));
        if options & 0x80 == 0 && !anonymous {
            if options & 0x100 == 0 {
                return Ok(hash_v1(name));
            }
            if options & 0x200 != 0 {
                return Ok(hash_v1(cstring(record, at + name.len() + 1)?));
            }
        }
    } else if matches!(kind, 0x1606 | 0x1607) {
        return Ok(hash_v1(
            record.get(4..8).context("Truncated source type hash")?,
        ));
    }
    Ok(jam_crc(record))
}

fn jam_crc(bytes: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new_with_initial(u32::MAX);
    hasher.update(bytes);
    !hasher.finalize()
}

#[derive(Clone)]
struct ImageSection {
    address: u64,
    size: u64,
    header: [u8; 40],
}
fn image_sections(layout: &Layout<Coff>) -> Result<Vec<ImageSection>> {
    let mut sections = Vec::new();
    for (id, record) in layout.merged_section_layouts.iter() {
        if id.as_u32() < 2 || record.mem_size == 0 {
            continue;
        }
        let name = layout
            .output_sections
            .name(id)
            .context("Missing PE section name")?
            .0;
        ensure!(name.len() <= 8, "PE section name exceeds 8 bytes");
        let mut header = [0; 40];
        header[..name.len()].copy_from_slice(name);
        put32(&mut header, 8, u32::try_from(record.mem_size)?);
        put32(
            &mut header,
            12,
            u32::try_from(record.mem_offset - layout.args().image_base)?,
        );
        put32(
            &mut header,
            16,
            u32::try_from((record.file_size + 511) & !511)?,
        );
        put32(&mut header, 20, u32::try_from(record.file_offset)?);
        put32(
            &mut header,
            36,
            layout.output_sections.output_info(id).section_attributes.0,
        );
        sections.push(ImageSection {
            address: record.mem_offset,
            size: record.mem_size,
            header,
        });
    }
    sections.sort_by_key(|s| s.address);
    Ok(sections)
}

fn section_offset(sections: &[ImageSection], address: u64) -> Option<(u16, u32)> {
    sections.iter().enumerate().find_map(|(index, section)| {
        (address >= section.address && address - section.address < section.size).then(|| {
            (
                u16::try_from(index + 1).unwrap(),
                u32::try_from(address - section.address).unwrap(),
            )
        })
    })
}

fn relocated_debug(
    layout: &Layout<Coff>,
    object: &ObjectLayout<Coff>,
    index: object::SectionIndex,
    sections: &[ImageSection],
) -> Result<Vec<u8>> {
    let section = object.object.section(index)?;
    let mut bytes = object.object.raw_section_data(section)?.to_vec();
    for relocation in object.object.relocations(index, &())?.rel_iter() {
        if relocation.kind == 0 {
            continue;
        }
        let at = relocation.offset as usize;
        let id = object
            .symbol_id_range
            .input_to_id(object::SymbolIndex(relocation.symbol as usize));
        let symbol = &object.object.symbols[relocation.symbol as usize];
        let discarded = symbol.section > 0
            && object.section_resolutions[symbol.section as usize - 1]
                .address()
                .is_none();
        let address = if discarded {
            None
        } else {
            layout
                .merged_symbol_resolution(id)
                .map(|r| r.raw_value)
                .or_else(|| {
                    if symbol.section > 0 {
                        object.section_resolutions[symbol.section as usize - 1]
                            .address()
                            .map(|va| va + u64::from(symbol.value))
                    } else if symbol.section == -1 {
                        Some(u64::from(symbol.value))
                    } else {
                        None
                    }
                })
        };
        let location = address.and_then(|address| section_offset(sections, address));
        match relocation.kind {
            10 => {
                let old = read16(&bytes, at)?;
                put16(
                    &mut bytes,
                    at,
                    match location {
                        Some((section, _)) => {
                            old.checked_add(section).context("Debug SECTION overflow")?
                        }
                        None => 0xffff,
                    },
                );
            }
            11 => {
                let old = read32(&bytes, at)?;
                put32(
                    &mut bytes,
                    at,
                    match location {
                        Some((_, offset)) => {
                            u32::try_from(i64::from(offset) + i64::from(old as i32))
                                .context("Debug SECREL overflow")?
                        }
                        None => 0,
                    },
                );
            }
            3 => {
                let old = read32(&bytes, at)?;
                put32(
                    &mut bytes,
                    at,
                    match address {
                        Some(va) => u32::try_from(
                            i128::from(va) - i128::from(layout.args().image_base)
                                + i128::from(old as i32),
                        )
                        .context("Debug ADDR32NB overflow")?,
                        None => 0,
                    },
                );
            }
            other => bail!("Unsupported CodeView relocation {other}"),
        }
    }
    Ok(bytes)
}

fn subsections(bytes: &[u8]) -> Result<Vec<(u32, &[u8])>> {
    ensure!(
        read32(bytes, 0)? == 4,
        "Unsupported CodeView symbol signature"
    );
    let mut at = 4;
    let mut out = Vec::new();
    while at < bytes.len() {
        let kind = read32(bytes, at)? & 0x7fffffff;
        let size = read32(bytes, at + 4)? as usize;
        at += 8;
        out.push((
            kind,
            bytes
                .get(at..at + size)
                .context("Truncated CodeView subsection")?,
        ));
        at = (at + size + 3) & !3;
        ensure!(at <= bytes.len(), "Truncated CodeView subsection padding");
    }
    Ok(out)
}

fn map_index(record: &mut [u8], at: usize, id: bool, map: &[(u32, bool)]) -> Result {
    let source = read32(record, at)?;
    if source < 0x1000 {
        return Ok(());
    }
    let &(target, is_id) = map
        .get((source - 0x1000) as usize)
        .context("Invalid CodeView symbol type index")?;
    ensure!(is_id == id, "Symbol type/ID reference mismatch");
    put32(record, at, target);
    Ok(())
}

fn remap_symbol(record: &mut [u8], map: &[(u32, bool)], ipi: &[&[u8]]) -> Result {
    let kind = read16(record, 2)?;
    let range_size = match kind {
        0x113f | 0x1141 | 0x1142 => Some(16),
        0x1140 | 0x1143 | 0x1145 => Some(20),
        0x1144 => Some(8),
        0x1177 => Some(24),
        _ => None,
    };
    if let Some(size) = range_size {
        ensure!(
            record.len() >= size && (record.len() - size) % 4 == 0,
            "Truncated CodeView variable range"
        );
    }
    let name_offset = match kind {
        0x110f | 0x1110 | 0x1146 | 0x1147 => Some(39),
        0x1103 => Some(22),
        0x110c | 0x110d | 0x1112 | 0x1113 => Some(14),
        0x113e => Some(10),
        0x1108 => Some(8),
        0x1101 => Some(8),
        0x113c => Some(26),
        0x1111 => Some(14),
        0x110b => Some(12),
        _ => None,
    };
    if let Some(at) = name_offset {
        cstring(record, at)?;
    }
    if kind == 0x1012 {
        ensure!(record.len() >= 30, "Truncated CodeView frame information");
    }
    match kind {
        0x1146 | 0x1147 => {
            map_index(record, 28, true, map)?;
            let index = read32(record, 28)?;
            if index >= 0x1000 {
                let id = ipi
                    .get((index - 0x1000) as usize)
                    .context("Invalid procedure ID")?;
                ensure!(
                    matches!(read16(id, 2)?, 0x1601 | 0x1602),
                    "Invalid procedure ID record"
                );
                put32(record, 28, read32(id, 8)?);
            }
            put16(record, 2, if kind == 0x1147 { 0x1110 } else { 0x110f });
        }
        0x110f | 0x1110 => map_index(record, 28, false, map)?,
        0x1107 | 0x1108 | 0x110c | 0x110d | 0x1112 | 0x1113 | 0x113e | 0x1153 | 0x1106 => {
            map_index(record, 4, false, map)?
        }
        0x110b | 0x1111 | 0x1171 => map_index(record, 8, false, map)?,
        0x114c => map_index(record, 4, true, map)?,
        0x114d | 0x115d => map_index(record, 12, true, map)?,
        0x1139 | 0x115e => map_index(record, 12, false, map)?,
        0x115a | 0x115b | 0x1168 => {
            let count = read32(record, 4)? as usize;
            ensure!(count <= record.len() / 4, "Invalid CodeView caller count");
            for i in 0..count {
                map_index(record, 8 + i * 4, true, map)?;
            }
        }
        0x114f => put16(record, 2, 6),
        6
        | 0x1101
        | 0x1102
        | 0x1103
        | 0x1105
        | 0x1012
        | 0x113c
        | 0x1116
        | 0x113d
        | 0x113a
        | 0x113f..=0x1145
        | 0x114e
        | 0x1159
        | 0x1124
        | 0x1177 => {}
        _ => bail!("Unsupported CodeView symbol record {kind:#x}"),
    }
    Ok(())
}

#[derive(Default)]
struct Strings {
    bytes: Vec<u8>,
    offsets: hashbrown::HashMap<Vec<u8>, u32>,
}
impl Strings {
    fn intern(&mut self, name: &[u8]) -> Result<u32> {
        if self.bytes.is_empty() {
            self.bytes.extend_from_slice(&[0, 0]);
            self.offsets.insert(Vec::new(), 1);
        }
        if name.is_empty() {
            return Ok(1);
        }
        if let Some(offset) = self.offsets.get(name) {
            return Ok(*offset);
        }
        let offset = u32::try_from(self.bytes.len())?;
        self.bytes.extend_from_slice(name);
        self.bytes.push(0);
        self.offsets.insert(name.to_vec(), offset);
        Ok(offset)
    }
    fn stream(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push32(&mut out, 0xeffeeffe);
        push32(&mut out, 1);
        push32(&mut out, self.bytes.len() as u32);
        out.extend_from_slice(&self.bytes);
        let buckets = (self.offsets.len() * 2 + 1).max(1);
        let mut hash = vec![0u32; buckets];
        let mut ordered: Vec<_> = self.offsets.iter().collect();
        ordered.sort_by_key(|(_, offset)| **offset);
        for (name, offset) in ordered {
            let mut i = hash_v1(name) as usize % buckets;
            while hash[i] != 0 {
                i = (i + 1) % buckets;
            }
            hash[i] = *offset;
        }
        push32(&mut out, buckets as u32);
        for offset in hash {
            push32(&mut out, offset);
        }
        push32(&mut out, self.offsets.len() as u32);
        out
    }
}

struct Module {
    name: String,
    symbols: Vec<u8>,
    lines: Vec<u8>,
    files: Vec<Vec<u8>>,
    contributions: Vec<[u8; 28]>,
    globals: Vec<Vec<u8>>,
    local_strings: Strings,
}

fn append_subsection(out: &mut Vec<u8>, kind: u32, body: &[u8]) {
    push32(out, kind);
    push32(out, body.len() as u32);
    out.extend_from_slice(body);
    pad4(out);
}

fn validate_lines(bytes: &[u8], checksums: &hashbrown::HashSet<u32>) -> Result {
    let flags = read16(bytes, 6)?;
    ensure!(flags & !1 == 0, "Invalid CodeView line flags");
    let code_size = read32(bytes, 8)?;
    let mut at = 12;
    while at < bytes.len() {
        ensure!(
            checksums.contains(&read32(bytes, at)?),
            "Invalid CodeView line file reference"
        );
        let count = read32(bytes, at + 4)? as usize;
        let size = read32(bytes, at + 8)? as usize;
        let stride = if flags & 1 != 0 { 12 } else { 8 };
        ensure!(
            count <= bytes.len() / stride && size == 12 + count * stride,
            "Invalid CodeView line block size"
        );
        ensure!(
            bytes.get(at..at + size).is_some(),
            "Truncated CodeView lines"
        );
        for index in 0..count {
            ensure!(
                read32(bytes, at + 12 + index * 8)? <= code_size,
                "CodeView line address exceeds contribution"
            );
        }
        at += size;
    }
    Ok(())
}

fn module(
    layout: &Layout<Coff>,
    object: &ObjectLayout<Coff>,
    sections: &[ImageSection],
    ipi: &[&[u8]],
    map: &[(u32, bool)],
    number: u16,
) -> Result<Module> {
    let mut strings = Strings::default();
    let mut debug = Vec::new();
    let mut contributions = Vec::new();
    for (index, section) in object.object.enumerate_sections() {
        match object.object.section_name(index)? {
            b".debug$T" => {}
            b".debug$S" => {
                if section.parent.is_some_and(|parent| {
                    object.section_resolutions[parent as usize]
                        .address()
                        .is_none()
                }) {
                    continue;
                }
                debug.push(relocated_debug(layout, object, index, sections)?);
            }
            _ => {
                if let Some(address) = object.section_resolutions[index.0].address() {
                    if let Some((segment, offset)) = section_offset(sections, address) {
                        let mut sc = [0; 28];
                        put16(&mut sc, 0, segment);
                        put32(&mut sc, 4, offset);
                        put32(&mut sc, 8, section.size);
                        put32(&mut sc, 12, section.flags);
                        put16(&mut sc, 16, number);
                        contributions.push(sc);
                    }
                }
            }
        }
    }
    let mut all = Vec::new();
    for bytes in &debug {
        all.extend(subsections(bytes)?);
    }
    let local_strings = all
        .iter()
        .find(|(kind, _)| *kind == 0xf3)
        .map(|(_, bytes)| *bytes)
        .unwrap_or(&[0]);
    let mut files = Vec::new();
    let mut checksums = Vec::new();
    let mut checksum_offsets = hashbrown::HashSet::new();
    for (_, data) in all.iter().filter(|(kind, _)| *kind == 0xf4) {
        let mut at = 0;
        while at < data.len() {
            let name = cstring(local_strings, read32(data, at)? as usize)?;
            let size = usize::from(*data.get(at + 4).context("Truncated CodeView checksum")?);
            let kind = *data.get(at + 5).context("Truncated CodeView checksum")?;
            ensure!(
                matches!((kind, size), (0, 0) | (1, 16) | (2, 20) | (3, 32)),
                "Invalid CodeView checksum kind or length"
            );
            let end = (at + 6 + size + 3) & !3;
            let mut entry = data
                .get(at..end)
                .context("Truncated CodeView checksum")?
                .to_vec();
            put32(&mut entry, 0, strings.intern(name)?);
            checksum_offsets.insert(at as u32);
            files.push(name.to_vec());
            checksums.extend_from_slice(&entry);
            at = end;
        }
    }
    let mut lines = Vec::new();
    if !checksums.is_empty() {
        append_subsection(&mut lines, 0xf4, &checksums);
    }
    let mut symbols = 4u32.to_le_bytes().to_vec();
    let mut globals = Vec::new();
    let mut scopes: Vec<(usize, bool)> = Vec::new();
    for (kind, body) in all {
        match kind {
            0xf1 => {
                for source in records(body)? {
                    let kind = read16(source, 2)?;
                    let opener = matches!(
                        kind,
                        0x110f | 0x1110 | 0x1146 | 0x1147 | 0x1103 | 0x114d | 0x115d
                    );
                    let closer = matches!(kind, 6 | 0x114f | 0x114e);
                    let inherited_dead = scopes.last().is_some_and(|(_, dead)| *dead);
                    let dead = inherited_dead
                        || match kind {
                            0x110f | 0x1110 | 0x1146 | 0x1147 => read16(source, 36)? == 0xffff,
                            0x1103 => read16(source, 20)? == 0xffff,
                            0x110c | 0x110d | 0x1112 | 0x1113 => read16(source, 12)? == 0xffff,
                            _ => false,
                        };
                    if opener && dead {
                        scopes.push((0, true));
                        continue;
                    }
                    if closer {
                        let (start, was_dead) =
                            scopes.pop().context("Unbalanced CodeView scope")?;
                        if was_dead {
                            continue;
                        }
                        let end = symbols.len() as u32;
                        put32(&mut symbols, start + 8, end);
                    } else if dead {
                        continue;
                    }
                    let mut record = source.to_vec();
                    remap_symbol(&mut record, map, ipi)?;
                    if opener {
                        let parent = scopes.last().map_or(0, |(at, _)| *at as u32);
                        put32(&mut record, 4, parent);
                        put32(&mut record, 8, 0);
                        scopes.push((symbols.len(), false));
                    }
                    pad4(&mut record);
                    let length = u16::try_from(record.len() - 2)?;
                    put16(&mut record, 0, length);
                    if scopes.is_empty()
                        && matches!(kind, 0x1107 | 0x1108 | 0x110c | 0x110d | 0x1112 | 0x1113)
                    {
                        globals.push(record);
                        continue;
                    }
                    symbols.extend_from_slice(&record);
                }
            }
            0xf2 => {
                if read16(body, 4)? != 0xffff {
                    validate_lines(body, &checksum_offsets)?;
                    append_subsection(&mut lines, kind, body);
                }
            }
            0xf6 => {
                let mut body = body.to_vec();
                let signature = read32(&body, 0)?;
                ensure!(signature <= 1, "Invalid inlinee line signature");
                let mut at = 4;
                while at < body.len() {
                    map_index(&mut body, at, true, map)?;
                    at += 12;
                    if signature == 1 {
                        let count = read32(&body, at)? as usize;
                        at += 4 + count * 4;
                    }
                    ensure!(at <= body.len(), "Truncated inlinee lines");
                }
                append_subsection(&mut lines, kind, &body);
            }
            0xf3 | 0xf4 => {}
            _ => bail!("Unsupported CodeView subsection {kind:#x}"),
        }
    }
    ensure!(scopes.is_empty(), "Unclosed CodeView scope");
    Ok(Module {
        name: object.input.to_string(),
        symbols,
        lines,
        files,
        contributions,
        globals,
        local_strings: strings,
    })
}

fn hash_v1(bytes: &[u8]) -> u32 {
    let mut value = 0u32;
    let mut chunks = bytes.chunks_exact(4);
    for chunk in &mut chunks {
        value ^= u32::from_le_bytes(chunk.try_into().unwrap());
    }
    let rest = chunks.remainder();
    if rest.len() >= 2 {
        value ^= u16::from_le_bytes(rest[..2].try_into().unwrap()) as u32;
    }
    if rest.len() % 2 != 0 {
        value ^= u32::from(rest[rest.len() - 1]);
    }
    value |= 0x20202020;
    value ^= value >> 11;
    value ^ (value >> 16)
}

fn hash_index(records: &[(&[u8], u32)]) -> Vec<u8> {
    let storage = bumpalo_herd::Herd::new();
    let mut order: Vec<_> = records
        .par_chunks(1024)
        .flat_map_iter(|chunk| {
            let member = storage.get();
            chunk.iter().map(move |(name, offset)| {
                let folded = if name.is_ascii() {
                    let folded = member.alloc_slice_copy(name);
                    folded.make_ascii_lowercase();
                    Some(&*folded)
                } else {
                    None
                };
                (hash_v1(name) % 4096, *name, folded, *offset)
            })
        })
        .collect();
    order.par_sort_unstable_by(|a, b| {
        a.0.cmp(&b.0)
            .then(a.1.len().cmp(&b.1.len()))
            .then_with(|| match (a.2, b.2) {
                (Some(a), Some(b)) => a.cmp(b),
                _ => a.1.cmp(b.1),
            })
            .then(a.3.cmp(&b.3))
    });
    let mut bitmap = [0u32; 129];
    let mut buckets = Vec::new();
    let mut previous = None;
    for (index, (bucket, _, _, _)) in order.iter().enumerate() {
        if previous != Some(*bucket) {
            bitmap[*bucket as usize / 32] |= 1 << (*bucket % 32);
            buckets.push(index as u32 * 12);
            previous = Some(*bucket);
        }
    }
    let mut out = Vec::with_capacity(16 + order.len() * 8 + (bitmap.len() + buckets.len()) * 4);
    push32(&mut out, u32::MAX);
    push32(&mut out, 0xeffe0000 + 19990810);
    push32(&mut out, order.len() as u32 * 8);
    push32(&mut out, (bitmap.len() + buckets.len()) as u32 * 4);
    for (_, _, _, offset) in order {
        push32(&mut out, offset + 1);
        push32(&mut out, 1);
    }
    for word in bitmap {
        push32(&mut out, word);
    }
    for offset in buckets {
        push32(&mut out, offset);
    }
    out
}

fn info_stream(named: &[(String, u32)], guid: [u8; 16]) -> Vec<u8> {
    let mut out = Vec::new();
    push32(&mut out, 20000404);
    push32(&mut out, u32::from_le_bytes(guid[..4].try_into().unwrap()));
    push32(&mut out, 1);
    out.extend_from_slice(&guid);
    let mut names = Vec::new();
    let capacity = (named.len() * 2 + 1).max(1);
    let mut entries = vec![None; capacity];
    for (name, stream) in named {
        let offset = names.len() as u32;
        names.extend_from_slice(name.as_bytes());
        names.push(0);
        let mut bucket = (hash_v1(name.as_bytes()) as u16 as usize) % capacity;
        while entries[bucket].is_some() {
            bucket = (bucket + 1) % capacity;
        }
        entries[bucket] = Some((offset, *stream));
    }
    push32(&mut out, names.len() as u32);
    out.extend_from_slice(&names);
    push32(&mut out, named.len() as u32);
    push32(&mut out, capacity as u32);
    let mut words = vec![0u32; capacity.div_ceil(32)];
    for (i, entry) in entries.iter().enumerate() {
        if entry.is_some() {
            words[i / 32] |= 1 << (i % 32);
        }
    }
    push32(&mut out, words.len() as u32);
    for word in words {
        push32(&mut out, word);
    }
    push32(&mut out, 0);
    for entry in entries.into_iter().flatten() {
        push32(&mut out, entry.0);
        push32(&mut out, entry.1);
    }
    push32(&mut out, 20140508);
    out
}

struct Msf {
    blocks: Vec<Vec<usize>>,
    directory: Vec<u8>,
    directory_blocks: Vec<usize>,
    map: usize,
    total: usize,
}

impl Msf {
    fn new(streams: &[Vec<u8>]) -> Result<Self> {
        const BLOCK: usize = 4096;
        let mut next = 3usize;
        let mut allocate = || {
            while next % BLOCK == 1 || next % BLOCK == 2 {
                next += 1;
            }
            let block = next;
            next += 1;
            block
        };
        let mut blocks = Vec::new();
        for stream in streams {
            blocks.push(
                (0..stream.len().div_ceil(BLOCK))
                    .map(|_| allocate())
                    .collect::<Vec<_>>(),
            );
        }
        let mut directory = Vec::new();
        push32(&mut directory, u32::try_from(streams.len())?);
        for stream in streams {
            push32(&mut directory, u32::try_from(stream.len())?);
        }
        for stream_blocks in &blocks {
            for block in stream_blocks {
                push32(&mut directory, u32::try_from(*block)?);
            }
        }
        let directory_blocks: Vec<_> = (0..directory.len().div_ceil(BLOCK))
            .map(|_| allocate())
            .collect();
        ensure!(
            directory_blocks.len() <= BLOCK / 4,
            "PDB MSF directory exceeds supported block map size"
        );
        let map = allocate();
        let total = next;
        u32::try_from(total)?;
        Ok(Self {
            blocks,
            directory,
            directory_blocks,
            map,
            total,
        })
    }

    fn size(&self) -> Result<usize> {
        self.total.checked_mul(4096).context("PDB size overflow")
    }

    fn write(&self, streams: &[Vec<u8>], out: &mut [u8]) -> Result {
        const BLOCK: usize = 4096;
        let Self {
            blocks,
            directory,
            directory_blocks,
            map,
            total,
        } = self;
        ensure!(out.len() == self.size()?, "PDB output size mismatch");
        let mut pages: Vec<&[u8]> = vec![&[]; *total];
        for (stream, stream_blocks) in streams.iter().zip(blocks) {
            for (chunk, block) in stream.chunks(BLOCK).zip(stream_blocks) {
                pages[*block] = chunk;
            }
        }
        for (chunk, block) in directory.chunks(BLOCK).zip(directory_blocks) {
            pages[*block] = chunk;
        }
        let copy = |(batch, bytes): (usize, &mut [u8])| {
            for (index, page) in bytes.chunks_mut(BLOCK).enumerate() {
                let block = batch * 256 + index;
                if matches!(block % BLOCK, 1 | 2) {
                    page.fill(0xff);
                } else {
                    let source = pages[block];
                    page[..source.len()].copy_from_slice(source);
                    page[source.len()..].fill(0);
                }
            }
        };
        if out.len() >= 16 * 1024 * 1024 {
            out.par_chunks_mut(BLOCK * 256).enumerate().for_each(copy);
        } else {
            out.chunks_mut(BLOCK * 256).enumerate().for_each(copy);
        }
        out[..32].copy_from_slice(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0");
        put32(out, 32, BLOCK as u32);
        put32(out, 36, 1);
        put32(out, 40, *total as u32);
        put32(out, 44, directory.len() as u32);
        put32(out, 52, *map as u32);
        for (index, block) in directory_blocks.iter().enumerate() {
            put32(out, map * BLOCK + index * 4, *block as u32);
        }
        for block in 0..*total {
            let page = 1 + (block / (BLOCK * 8)) * BLOCK;
            let at = page * BLOCK + (block % (BLOCK * 8)) / 8;
            out[at] &= !(1 << (block % 8));
            out[at + BLOCK] &= !(1 << (block % 8));
        }
        Ok(())
    }
}

#[cfg(test)]
fn msf(streams: &[Vec<u8>]) -> Result<Vec<u8>> {
    let msf = Msf::new(streams)?;
    let mut out = vec![0; msf.size()?];
    msf.write(streams, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn type_input(records: &[(u16, &[u8])]) -> Vec<u8> {
        let mut bytes = 4u32.to_le_bytes().to_vec();
        for &(kind, body) in records {
            let mut record = vec![0; 4];
            put16(&mut record, 2, kind);
            record.extend_from_slice(body);
            pad4(&mut record);
            let len = (record.len() - 2) as u16;
            put16(&mut record, 0, len);
            bytes.extend_from_slice(&record);
        }
        bytes
    }

    #[test]
    fn structural_hash_collisions_compare_canonical_records() {
        let args = [0u8; 4];
        let mut procedure = vec![0; 12];
        put32(&mut procedure, 0, 0x74);
        put32(&mut procedure, 8, 0x1000);
        let bytes = type_input(&[(0x1201, &args), (0x1008, &procedure)]);
        let mut prepared = prepare_types(&bytes).unwrap();
        for record in &mut prepared {
            record.hash = 7;
        }
        let herd = bumpalo_herd::Herd::new();
        let mut types = Types::new(&herd);
        let first = types.merge(&prepared).unwrap();
        assert_eq!(first, [(0x1000, false), (0x1001, false)]);
        assert_eq!(types.merge(&prepared).unwrap(), first);
        assert_eq!(types.tpi.len(), 2);
    }

    #[test]
    fn invalid_type_references_and_truncated_records_fail() {
        let forward = type_input(&[(0x1201, &[1, 0, 0, 0, 0, 0x10, 0, 0])]);
        assert!(prepare_types(&forward).is_err());
        let string_id = [0, 0, 0, 0, b'x', 0];
        let invalid = type_input(&[(0x1605, &string_id), (0x1001, &[0, 0x10, 0, 0, 0, 0])]);
        assert!(prepare_types(&invalid).is_err());
        assert!(records(&[]).unwrap().is_empty());
        for bytes in [vec![0, 0], vec![10, 0, 1, 0x10]] {
            assert!(records(&bytes).is_err());
        }
        assert!(prepare_types(&type_input(&[(0x1001, &[0x74, 0, 0, 0])])).is_err());
    }

    #[test]
    fn truncated_lines_and_invalid_file_references_fail() {
        let mut bytes = vec![0; 32];
        put32(&mut bytes, 8, 8);
        put32(&mut bytes, 16, 1);
        put32(&mut bytes, 20, 20);
        let files = [0].into_iter().collect();
        validate_lines(&bytes, &files).unwrap();
        for length in [0, 5, 11, 16, 31] {
            assert!(validate_lines(&bytes[..length], &files).is_err());
        }
        put32(&mut bytes, 12, 1);
        assert!(validate_lines(&bytes, &files).is_err());
        put32(&mut bytes, 12, 0);
        put32(&mut bytes, 24, 9);
        assert!(validate_lines(&bytes, &files).is_err());
    }

    #[test]
    fn optimized_crc_matches_bounded_scalar_crc() {
        let bytes: Vec<_> = (0..1000).map(|i| i as u8).collect();
        for length in [0, 1, 2, 3, 16, 63, 64, 65, 511, 997] {
            for offset in 0..3 {
                let input = &bytes[offset..offset + length];
                let mut crc = 0u32;
                for &byte in input {
                    crc ^= u32::from(byte);
                    for _ in 0..8 {
                        crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb88320 } else { 0 };
                    }
                }
                assert_eq!(jam_crc(input), crc);
            }
        }
    }

    #[test]
    fn msf_stream_pages_do_not_overlap_reserved_free_page_maps() {
        let bytes = vec![0x5a; 17 * 1024 * 1024];
        let output = msf(&[bytes.clone()]).unwrap();
        let layout = Msf::new(&[bytes.clone()]).unwrap();
        let mut dirty = vec![0xcc; layout.size().unwrap()];
        for threads in [1, 2, 4] {
            dirty.fill(0xcc);
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| layout.write(&[bytes.clone()], &mut dirty))
                .unwrap();
            assert_eq!(dirty, output);
        }
        let map = read32(&output, 52).unwrap() as usize * 4096;
        let directory = read32(&output, map).unwrap() as usize * 4096;
        assert_eq!(read32(&output, directory).unwrap(), 1);
        assert_eq!(read32(&output, directory + 4).unwrap(), bytes.len() as u32);
        // This crosses the first reserved FPM pair at blocks 4097 and 4098.
        let mut reconstructed = Vec::new();
        let directory_size = read32(&output, 44).unwrap() as usize;
        let mut directory_bytes = Vec::new();
        for i in 0..directory_size.div_ceil(4096) {
            let block = read32(&output, map + i * 4).unwrap() as usize;
            directory_bytes.extend_from_slice(&output[block * 4096..(block + 1) * 4096]);
        }
        for i in 0..bytes.len().div_ceil(4096) {
            let block = read32(&directory_bytes, 8 + i * 4).unwrap() as usize;
            assert!(!matches!(block % 4096, 1 | 2));
            reconstructed.extend_from_slice(&output[block * 4096..(block + 1) * 4096]);
        }
        reconstructed.truncate(bytes.len());
        assert_eq!(reconstructed, bytes);
    }
}

pub(super) fn build(layout: &Layout<Coff>) -> Result<Pdb> {
    let _scope = crate::timing_guard!("Build PDB");
    let path = output_path(layout.args());
    ensure!(
        path != layout.args().common.output,
        "PDB and image paths conflict"
    );
    let sections = image_sections(layout)?;
    let type_storage = bumpalo_herd::Herd::new();
    let mut types = Types::new(&type_storage);
    let mut strings = Strings::default();
    strings.intern(b"")?;
    let mut objects = Vec::new();
    {
        for group in &layout.group_layouts {
            for file in &group.files {
                if let FileLayout::Object(object) = file {
                    if object.object.import.is_some() {
                        continue;
                    }
                    let mut data = &[4, 0, 0, 0][..];
                    for (index, section) in object.object.enumerate_sections() {
                        if object.object.section_name(index)? == b".debug$T" {
                            data = object.object.raw_section_data(section)?;
                        }
                    }
                    objects.push((object, data));
                }
            }
        }
    }
    let prepared = {
        crate::timing_phase!("CodeView structural type hashing");
        objects
            .par_iter()
            .map(|(object, data)| {
                prepare_types(data)
                    .with_context(|| format!("Processing CodeView types in {}", object.input))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .collect::<Result<Vec<_>>>()?
    };
    let objects = {
        crate::timing_phase!("CodeView canonical type merging");
        objects
            .into_iter()
            .zip(&prepared)
            .map(|((object, _), records)| Ok((object, types.merge(records)?)))
            .collect::<Result<Vec<_>>>()?
    };
    prepared.into_par_iter().for_each(drop);
    let mut modules = {
        crate::timing_phase!("CodeView symbols and address conversion");
        objects
            .par_iter()
            .enumerate()
            .map(|(number, (object, map))| {
                module(
                    layout,
                    object,
                    &sections,
                    &types.ipi,
                    map,
                    u16::try_from(number)?,
                )
                .with_context(|| format!("Processing CodeView in {}", object.input))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .collect::<Result<Vec<_>>>()?
    };
    for module in &mut modules {
        let mut at = 0;
        while at < module.lines.len() {
            let kind = read32(&module.lines, at)?;
            let size = read32(&module.lines, at + 4)? as usize;
            let end = at + 8 + size;
            if kind == 0xf4 {
                let mut entry = at + 8;
                while entry < end {
                    let name = cstring(
                        &module.local_strings.bytes,
                        read32(&module.lines, entry)? as usize,
                    )?;
                    put32(&mut module.lines, entry, strings.intern(name)?);
                    entry = (entry + 6 + usize::from(module.lines[entry + 4]) + 3) & !3;
                }
            }
            at = (end + 3) & !3;
        }
    }
    crate::timing_phase!("PDB type hashing");
    let mut streams = vec![Vec::new(); 12];
    let (tpi, tpi_hash) = Types::stream(&types.tpi, 10)?;
    let (ipi, ipi_hash) = Types::stream(&types.ipi, 11)?;
    streams[2] = tpi;
    streams[10] = tpi_hash;
    streams[4] = ipi;
    streams[11] = ipi_hash;
    streams[5] = strings.stream();
    crate::timing_phase!("PDB public and global indexes");
    let mut publics = Vec::new();
    let mut public_addresses = Vec::new();
    let mut names_seen = hashbrown::HashSet::new();
    for group in &layout.group_layouts {
        for file in &group.files {
            if let FileLayout::Object(object) = file {
                for (index, symbol) in object.object.symbols.iter().enumerate() {
                    if symbol.class != 2 || symbol.section <= 0 {
                        continue;
                    }
                    let id = object
                        .symbol_id_range
                        .input_to_id(object::SymbolIndex(index));
                    let Some(resolution) = layout.merged_symbol_resolution(id) else {
                        continue;
                    };
                    let Some((segment, offset)) = section_offset(&sections, resolution.raw_value)
                    else {
                        continue;
                    };
                    let name = object.object.symbol_name(symbol)?;
                    if !names_seen.insert(name) {
                        continue;
                    }
                    let start = streams[6].len() as u32;
                    let mut record = vec![0; 14];
                    put16(&mut record, 2, 0x110e);
                    let flags =
                        if read32(&sections[segment as usize - 1].header, 36)? & 0x20000000 != 0 {
                            2
                        } else {
                            0
                        };
                    put32(&mut record, 4, flags);
                    put32(&mut record, 8, offset);
                    put16(&mut record, 12, segment);
                    record.extend_from_slice(name);
                    record.push(0);
                    pad4(&mut record);
                    let length = u16::try_from(record.len() - 2)?;
                    put16(&mut record, 0, length);
                    streams[6].extend_from_slice(&record);
                    publics.push((name, start));
                    public_addresses.push((segment, offset, start));
                }
            }
        }
    }
    let public_hash = hash_index(&publics);
    streams[7] = vec![0; 28];
    put32(&mut streams[7], 0, public_hash.len() as u32);
    put32(&mut streams[7], 4, public_addresses.len() as u32 * 4);
    streams[7].extend_from_slice(&public_hash);
    public_addresses.sort_unstable();
    for (_, _, offset) in public_addresses {
        push32(&mut streams[7], offset);
    }
    let mut global_records = Vec::new();
    let mut global_offsets: hashbrown::HashMap<&[u8], u32> = Default::default();
    let mut module_info = Vec::new();
    let mut contribution_records = Vec::new();
    let mut file_info = Vec::new();
    push16(&mut file_info, u16::try_from(modules.len())?);
    push16(
        &mut file_info,
        modules.iter().map(|m| m.files.len()).sum::<usize>() as u16,
    );
    let mut file_names = Strings::default();
    for i in 0..modules.len() {
        push16(&mut file_info, i as u16);
    }
    for module in &modules {
        push16(&mut file_info, u16::try_from(module.files.len())?);
    }
    for module in &modules {
        for name in &module.files {
            push32(&mut file_info, file_names.intern(name)?);
        }
    }
    file_info.extend_from_slice(&file_names.bytes);
    pad4(&mut file_info);
    for (index, module) in modules.iter().enumerate() {
        let has_debug = module.symbols.len() > 4 || !module.lines.is_empty();
        let module_stream = if has_debug {
            u16::try_from(streams.len())?
        } else {
            u16::MAX
        };
        let start = module_info.len();
        module_info.resize(start + 64, 0);
        if let Some(sc) = module.contributions.first() {
            module_info[start + 4..start + 32].copy_from_slice(sc);
        }
        put16(&mut module_info, start + 34, module_stream);
        put32(
            &mut module_info,
            start + 36,
            if has_debug {
                module.symbols.len() as u32
            } else {
                0
            },
        );
        put32(&mut module_info, start + 44, module.lines.len() as u32);
        put16(&mut module_info, start + 48, module.files.len() as u16);
        module_info.extend_from_slice(module.name.as_bytes());
        module_info.push(0);
        module_info.extend_from_slice(module.name.as_bytes());
        module_info.push(0);
        pad4(&mut module_info);
        if has_debug {
            let mut stream = Vec::with_capacity(module.symbols.len() + module.lines.len() + 4);
            stream.extend_from_slice(&module.symbols);
            stream.extend_from_slice(&module.lines);
            push32(&mut stream, 0);
            streams.push(stream);
        }
        contribution_records.extend(module.contributions.iter().copied());
        let mut at = 4;
        for record in records(&module.symbols[4..])? {
            let kind = read16(record, 2)?;
            if matches!(kind, 0x110f | 0x1110) {
                let name = cstring(record, 39)?;
                let mut reference = vec![0; 14];
                put16(
                    &mut reference,
                    2,
                    if kind == 0x1110 { 0x1125 } else { 0x1127 },
                );
                put32(&mut reference, 8, at);
                put16(&mut reference, 12, u16::try_from(index + 1)?);
                reference.extend_from_slice(name);
                reference.push(0);
                pad4(&mut reference);
                let len = u16::try_from(reference.len() - 2)?;
                put16(&mut reference, 0, len);
                global_records.push((name, streams[6].len() as u32));
                streams[6].extend_from_slice(&reference);
            } else if matches!(kind, 0x1107 | 0x1108 | 0x110c | 0x110d | 0x1112 | 0x1113) {
                let name_at = match kind {
                    0x1107 => 8 + numeric_length(record, 8)?,
                    0x1108 => 8,
                    _ => 14,
                };
                let name = cstring(record, name_at)?;
                if !global_offsets.contains_key(record) {
                    let offset = streams[6].len() as u32;
                    global_offsets.insert(record, offset);
                    global_records.push((name, offset));
                    streams[6].extend_from_slice(record);
                }
            }
            at += record.len() as u32;
        }
        for record in &module.globals {
            if global_offsets.contains_key(record.as_slice()) {
                continue;
            }
            let kind = read16(record, 2)?;
            let name_at = match kind {
                0x1107 => 8 + numeric_length(record, 8)?,
                0x1108 => 8,
                _ => 14,
            };
            let name = cstring(record, name_at)?;
            let offset = streams[6].len() as u32;
            global_offsets.insert(record, offset);
            global_records.push((name, offset));
            streams[6].extend_from_slice(record);
        }
    }
    streams[8] = hash_index(&global_records);
    for section in &sections {
        streams[9].extend_from_slice(&section.header);
    }
    let mut section_map = Vec::new();
    push16(&mut section_map, sections.len() as u16);
    push16(&mut section_map, sections.len() as u16);
    for (i, section) in sections.iter().enumerate() {
        let mut entry = vec![0; 20];
        let flags = read32(&section.header, 36)?;
        put16(
            &mut entry,
            0,
            0x108
                | u16::from(flags & 0x40000000 != 0)
                | if flags & 0x80000000 != 0 { 2 } else { 0 }
                | if flags & 0x20000000 != 0 { 4 } else { 0 },
        );
        put16(&mut entry, 6, (i + 1) as u16);
        put16(&mut entry, 8, 0xffff);
        put16(&mut entry, 10, 0xffff);
        put32(&mut entry, 16, u32::try_from(section.size)?);
        section_map.extend_from_slice(&entry);
    }
    let mut ec_names = Strings::default();
    ec_names.intern(b"")?;
    let ec_names = ec_names.stream();
    let contribution_key = |record: &[u8; 28]| {
        (
            u16::from_le_bytes(record[..2].try_into().unwrap()),
            u32::from_le_bytes(record[4..8].try_into().unwrap()),
        )
    };
    if contribution_records.len() >= 16384 {
        contribution_records.par_sort_by_key(contribution_key);
    } else {
        contribution_records.sort_by_key(contribution_key);
    }
    let mut contributions = Vec::new();
    push32(&mut contributions, 0xeffe0000 + 19970605);
    for record in contribution_records {
        contributions.extend_from_slice(&record);
    }
    let mut dbi = vec![0; 64];
    put32(&mut dbi, 0, u32::MAX);
    put32(&mut dbi, 4, 19990903);
    put32(&mut dbi, 8, 1);
    put16(&mut dbi, 12, 8);
    put16(&mut dbi, 14, 0x8e00);
    put16(&mut dbi, 16, 7);
    put16(&mut dbi, 18, 140);
    put16(&mut dbi, 20, 6);
    put32(&mut dbi, 24, module_info.len() as u32);
    put32(&mut dbi, 28, contributions.len() as u32);
    put32(&mut dbi, 32, section_map.len() as u32);
    put32(&mut dbi, 36, file_info.len() as u32);
    put32(&mut dbi, 48, 22);
    put32(&mut dbi, 52, ec_names.len() as u32);
    put16(&mut dbi, 58, 0x8664);
    dbi.extend_from_slice(&module_info);
    dbi.extend_from_slice(&contributions);
    dbi.extend_from_slice(&section_map);
    dbi.extend_from_slice(&file_info);
    dbi.extend_from_slice(&ec_names);
    for i in 0..11 {
        push16(&mut dbi, if i == 5 { 9 } else { 0xffff });
    }
    streams[3] = dbi;
    let mut named_streams = vec![("/names".to_owned(), 5u32)];
    let mut injected = Vec::new();
    for group in &layout.group_layouts {
        for file in &group.files {
            if let FileLayout::Object(object) = file {
                if let Some(assets) = object.object.pdb_assets() {
                    for asset in assets {
                        let virtual_name = asset.name.to_ascii_lowercase().replace('/', "\\");
                        let name_index = strings.intern(asset.name.as_bytes())?;
                        let virtual_index = strings.intern(virtual_name.as_bytes())?;
                        let mut entry = vec![0; 40];
                        put32(&mut entry, 0, 40);
                        put32(&mut entry, 4, 19980827);
                        let crc = jam_crc(asset.data);
                        put32(&mut entry, 8, crc);
                        put32(&mut entry, 12, u32::try_from(asset.data.len())?);
                        put32(&mut entry, 16, name_index);
                        put32(&mut entry, 20, strings.intern(b"")?);
                        put32(&mut entry, 24, virtual_index);
                        injected.push((virtual_name.clone(), virtual_index, entry));
                        named_streams
                            .push((format!("/src/files/{virtual_name}"), streams.len() as u32));
                        streams.push(asset.data.to_vec());
                    }
                }
            }
        }
    }
    if !injected.is_empty() {
        let capacity = injected.len() * 2 + 1;
        let mut buckets = vec![None; capacity];
        for entry in injected {
            // DIA hashes injected-source entries by the low 16 bits of their /names ID.
            let mut bucket = usize::from(entry.1 as u16) % capacity;
            while buckets[bucket].is_some() {
                bucket = (bucket + 1) % capacity;
            }
            buckets[bucket] = Some(entry);
        }
        let count = buckets.iter().filter(|entry| entry.is_some()).count();
        let mut stream = vec![0; 64];
        put32(&mut stream, 0, 19980827);
        push32(&mut stream, count as u32);
        push32(&mut stream, capacity as u32);
        let mut present = vec![0u32; capacity.div_ceil(32)];
        for (i, entry) in buckets.iter().enumerate() {
            if entry.is_some() {
                present[i / 32] |= 1 << (i % 32);
            }
        }
        push32(&mut stream, present.len() as u32);
        for word in present {
            push32(&mut stream, word);
        }
        push32(&mut stream, 0);
        for (_, key, value) in buckets.into_iter().flatten() {
            push32(&mut stream, key);
            stream.extend_from_slice(&value);
        }
        let len = stream.len() as u32;
        put32(&mut stream, 4, len);
        named_streams.push(("/src/headerblock".into(), streams.len() as u32));
        streams.push(stream);
    }
    streams[5] = strings.stream();
    crate::timing_phase!("PDB identity and MSF layout");
    let mut hasher = blake3::Hasher::new();
    for stream in &streams {
        hasher.update(&(stream.len() as u64).to_le_bytes());
        if stream.len() >= 1024 * 1024 {
            hasher.update_rayon(stream);
        } else {
            hasher.update(stream);
        }
    }
    let guid: [u8; 16] = hasher.finalize().as_bytes()[..16].try_into().unwrap();
    streams[1] = info_stream(&named_streams, guid);
    Ok(Pdb {
        msf: Msf::new(&streams)?,
        streams,
        guid,
        path,
    })
}
