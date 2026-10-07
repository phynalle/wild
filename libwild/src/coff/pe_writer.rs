//! PE encoding from the shared engine's finalized addresses and allocations.
#[allow(clippy::too_many_arguments)]
fn encode_headers(
    image: &mut [u8],
    args: &CoffArgs,
    outputs: &[OutputSection],
    entry: u64,
    headers: u32,
    image_size: u32,
    text: Option<usize>,
    import_directory: (u32, u32),
    exception_directory: (u32, u32),
    relocation_directory: (u32, u32),
    tls_directory: (u32, u32),
    load_config: (u32, u32),
    iat_directory: (u32, u32),
    export_directory: (u32, u32),
    debug_directory: (u32, u32),
) -> Result {
    ensure!(
        outputs.len() <= 96,
        "Windows PE loader supports at most 96 sections"
    );
    image[..2].copy_from_slice(b"MZ");
    put16(image, 2, 0x90);
    put16(image, 4, 3);
    put16(image, 8, 4);
    put16(image, 12, 0xffff);
    put16(image, 16, 0xb8);
    put16(image, 24, 0x40);
    put32(image, 0x3c, 0x80);
    image[0x80..0x84].copy_from_slice(b"PE\0\0");
    put16(image, 0x84, 0x8664);
    put16(image, 0x86, outputs.len() as u16);
    put16(image, 0x94, 240);
    put16(
        image,
        0x96,
        2 | if args.large_address_aware { 0x20 } else { 0 } | if args.is_dll { 0x2000 } else { 0 },
    );
    let opt = 0x98;
    put16(image, opt, 0x20b);
    image[opt + 2] = 1;
    put32(
        image,
        opt + 4,
        outputs
            .iter()
            .filter(|s| s.flags & 0x20 != 0)
            .map(|s| align(s.raw_len, 512))
            .sum(),
    );
    put32(
        image,
        opt + 8,
        outputs
            .iter()
            .filter(|s| s.flags & 0x40 != 0)
            .map(|s| align(s.raw_len, 512))
            .sum(),
    );
    put32(
        image,
        opt + 12,
        outputs
            .iter()
            .filter(|s| s.flags & 0x80 != 0)
            .map(|s| s.size)
            .sum(),
    );
    put32(image, opt + 16, u32::try_from(entry)?);
    put32(image, opt + 20, text.map_or(0, |i| outputs[i].rva));
    put64(image, opt + 24, args.image_base);
    put32(image, opt + 32, 4096);
    put32(image, opt + 36, 512);
    put16(image, opt + 40, 6);
    put16(image, opt + 48, args.subsystem_version.0);
    put16(image, opt + 50, args.subsystem_version.1);
    put32(image, opt + 56, image_size);
    put32(image, opt + 60, headers);
    put16(
        image,
        opt + 68,
        if args.subsystem == Some(Subsystem::Windows) {
            2
        } else {
            3
        },
    );
    put16(
        image,
        opt + 70,
        0x8000
            | if args.nx_compat { 0x100 } else { 0 }
            | if args.dynamic_base { 0x40 } else { 0 }
            | if args.dynamic_base && args.high_entropy_va {
                0x20
            } else {
                0
            },
    );
    put64(image, opt + 72, args.stack.0);
    put64(image, opt + 80, args.stack.1);
    put64(image, opt + 88, args.heap.0);
    put64(image, opt + 96, args.heap.1);
    put32(image, opt + 108, 16);
    for (i, (rva, size)) in [
        (0, export_directory),
        (1, import_directory),
        (3, exception_directory),
        (5, relocation_directory),
        (6, debug_directory),
        (9, tls_directory),
        (10, load_config),
        (12, iat_directory),
    ] {
        if size > 0 {
            put32(image, opt + 112 + i * 8, rva);
            put32(image, opt + 116 + i * 8, size);
        }
    }
    for (i, out) in outputs.iter().enumerate() {
        let sh = opt + 240 + i * 40;
        image[sh..sh + out.name.len()].copy_from_slice(out.name.as_bytes());
        put32(image, sh + 8, out.size);
        put32(image, sh + 12, out.rva);
        put32(image, sh + 16, align(out.raw_len, 512));
        put32(image, sh + 20, out.raw);
        put32(image, sh + 36, out.flags);
    }
    Ok(())
}
use super::backend::Coff;
use crate::args::coff::{CoffArgs, Subsystem};
use crate::error::{Context as _, Result};
use crate::file_writer::SizedOutput;
use crate::layout::{FileLayout, Layout, ObjectLayout};
use crate::platform::{ObjectFile as _, RelocationSequence as _, Symbol as _};
use crate::symbol::UnversionedSymbolName;
use crate::{OutputFileData, bail, ensure};
use rayon::prelude::*;

struct OutputSection {
    id: crate::output_section_id::OutputSectionId,
    name: String,
    flags: u32,
    size: u32,
    raw_len: u32,
    rva: u32,
    raw: u32,
}
fn align(v: u32, a: u32) -> u32 {
    (v + a - 1) & !(a - 1)
}
fn u16_at(b: &[u8], p: usize) -> u16 {
    u16::from_le_bytes(b[p..p + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(b[p..p + 8].try_into().unwrap())
}
fn put16(b: &mut [u8], p: usize, v: u16) {
    b[p..p + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], p: usize, v: u32) {
    b[p..p + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], p: usize, v: u64) {
    b[p..p + 8].copy_from_slice(&v.to_le_bytes());
}

fn named_address(layout: &Layout<Coff>, name: &str) -> Option<u64> {
    let id = layout
        .symbol_db
        .get_unversioned(&UnversionedSymbolName::prehashed(name.as_bytes()))?;
    layout.merged_symbol_resolution(id).map(|r| r.raw_value)
}

fn file_offset(outputs: &[OutputSection], base: u64, address: u64) -> Result<usize> {
    let rva = u32::try_from(address.checked_sub(base).context("Invalid PE address")?)?;
    let section = outputs
        .iter()
        .find(|s| rva >= s.rva && rva - s.rva < s.size)
        .with_context(|| format!("Unallocated PE address {address:#x} (RVA {rva:#x})"))?;
    Ok((section.raw + rva - section.rva) as usize)
}

pub(super) fn write<O: OutputFileData>(
    output: &mut SizedOutput<O>,
    layout: &Layout<Coff>,
    pdb: Option<&super::pdb::Pdb>,
) -> Result {
    let args = layout.args();
    let mut outputs = Vec::new();
    for (id, record) in layout.merged_section_layouts.iter() {
        if id.as_u32() < 2 || record.mem_size == 0 {
            continue;
        }
        let name = layout
            .output_sections
            .name(id)
            .context("PE output section has no name")?;
        ensure!(name.0.len() <= 8, "PE section name exceeds 8 bytes");
        outputs.push(OutputSection {
            id,
            name: std::str::from_utf8(name.0)?.to_owned(),
            flags: layout.output_sections.output_info(id).section_attributes.0,
            size: u32::try_from(record.mem_size)
                .with_context(|| format!("PE section {name} size {:#x}", record.mem_size))?,
            raw_len: u32::try_from(record.file_size)?,
            rva: u32::try_from(
                record
                    .mem_offset
                    .checked_sub(args.image_base)
                    .with_context(|| {
                        format!("PE section {name} lies below image base: {record:?}")
                    })?,
            )
            .with_context(|| {
                format!(
                    "PE section {name} address {:#x}, base {:#x}",
                    record.mem_offset, args.image_base
                )
            })?,
            raw: u32::try_from(record.file_offset)?,
        });
    }
    outputs.sort_by_key(|s| s.rva);
    let initially_zeroed = output.out.initially_zeroed();
    let image = &mut output.out[..];
    if !initially_zeroed {
        image.fill(0);
    }
    let mut base_relocations = Vec::new();
    let mut descriptors = Vec::new();
    let mut iat_range: Option<(u32, u32)> = None;
    let copy_and_relocate = crate::timing_guard!("PE copy and relocate");
    let mut jobs = Vec::new();
    for group in &layout.group_layouts {
        for file in &group.files {
            let FileLayout::Object(object) = file else {
                continue;
            };
            for (index, section) in object.object.enumerate_sections() {
                let Some(address) = object.section_resolutions[index.0].address() else {
                    continue;
                };
                if section.flags & 0x60 == 0 || section.size == 0 {
                    continue;
                }
                let start = file_offset(&outputs, args.image_base, address).with_context(|| {
                    format!(
                        "Writing {} {}",
                        object.input,
                        object.object.section_display_name(index)
                    )
                })?;
                let end = start
                    .checked_add(section.size as usize)
                    .context("PE section size overflow")?;
                ensure!(end <= image.len(), "PE section exceeds output");
                jobs.push((jobs.len(), object, index, address, start, end));
                if object.object.section_name(index)? == b".idata$2" {
                    descriptors.push((u32::try_from(address - args.image_base)?, section.size));
                }
                if object.object.section_name(index)? == b".idata$5" {
                    let start = u32::try_from(address - args.image_base)?;
                    let end = start.checked_add(section.size).context("PE IAT overflow")?;
                    iat_range = Some(
                        iat_range.map_or((start, end), |old| (old.0.min(start), old.1.max(end))),
                    );
                }
            }
        }
    }
    jobs.sort_unstable_by_key(|job| job.4);
    let mut remaining = &mut image[..];
    let mut offset = 0;
    let mut regions = Vec::with_capacity(jobs.len());
    for job in jobs {
        ensure!(job.4 >= offset, "Overlapping PE output allocations");
        let (_, tail) = remaining.split_at_mut(job.4 - offset);
        let (bytes, tail) = tail.split_at_mut(job.5 - job.4);
        remaining = tail;
        offset = job.5;
        regions.push((job, bytes));
    }
    let results: Vec<_> = regions
        .par_chunks_mut(256)
        .map(|chunk| {
            let mut relocations = Vec::new();
            let mut errors = Vec::new();
            for (job, bytes) in chunk {
                let (order, object, index, address, _, _) = *job;
                let result = (|| {
                    let section = object.object.section(index)?;
                    object.object.copy_section_data(section, bytes)?;
                    relocate(
                        layout,
                        object,
                        index,
                        address,
                        &outputs,
                        bytes,
                        &mut relocations,
                    )
                })()
                .with_context(|| {
                    format!(
                        "Relocating {} {}",
                        object.input,
                        object.object.section_display_name(index)
                    )
                });
                if let Err(error) = result {
                    errors.push((order, error));
                }
            }
            (relocations, errors)
        })
        .collect();
    drop(regions);
    let mut errors = Vec::new();
    for (relocations, chunk_errors) in results {
        base_relocations.extend(relocations);
        errors.extend(chunk_errors);
    }
    if let Some((_, error)) = errors.into_iter().min_by_key(|(order, _)| *order) {
        return Err(error);
    }
    drop(copy_and_relocate);
    let _directories_and_headers = crate::timing_guard!("PE directories and headers");
    base_relocations.sort_unstable();
    base_relocations.dedup();
    let mut relocation_directory = (0, 0);
    if let Some(reloc) = outputs.iter().find(|s| s.name == ".reloc") {
        let mut encoded = Vec::new();
        let mut cursor = 0;
        while cursor < base_relocations.len() {
            let page = base_relocations[cursor].0 & !4095;
            let start = encoded.len();
            encoded.resize(start + 8, 0);
            while cursor < base_relocations.len() && base_relocations[cursor].0 & !4095 == page {
                let (rva, kind) = base_relocations[cursor];
                encoded.extend_from_slice(&((kind << 12) | (rva & 4095) as u16).to_le_bytes());
                cursor += 1;
            }
            while encoded.len() % 4 != 0 {
                encoded.push(0);
            }
            let size = u32::try_from(encoded.len() - start)?;
            put32(&mut encoded, start, page);
            put32(&mut encoded, start + 4, size);
        }
        ensure!(
            encoded.len() <= reloc.raw_len as usize,
            "PE base relocations exceed shared allocation"
        );
        image[reloc.raw as usize..reloc.raw as usize + encoded.len()].copy_from_slice(&encoded);
        relocation_directory = (reloc.rva, encoded.len() as u32);
    }
    let mut exception_directory = (0, 0);
    if let Some(pdata) = outputs.iter().find(|s| s.name == ".pdata") {
        ensure!(pdata.size % 12 == 0, "Invalid PE exception table size");
        let bytes = &mut image[pdata.raw as usize..(pdata.raw + pdata.size) as usize];
        let mut records: Vec<[u8; 12]> = bytes
            .chunks_exact(12)
            .filter(|b| b.iter().any(|v| *v != 0))
            .map(|b| b.try_into().unwrap())
            .collect();
        records.sort_by_key(|b| u32_at(b, 0));
        records.dedup();
        bytes.fill(0);
        for (index, record) in records.iter().enumerate() {
            bytes[index * 12..index * 12 + 12].copy_from_slice(record);
        }
        exception_directory = (pdata.rva, (records.len() * 12) as u32);
    }
    descriptors.sort_unstable();
    let import_directory = descriptors.first().map_or((0, 0), |first| {
        (first.0, descriptors.iter().map(|d| d.1).sum())
    });
    let tls_directory = if let Some(address) = named_address(layout, "_tls_used") {
        let offset = file_offset(&outputs, args.image_base, address)?;
        ensure!(
            image.get(offset..offset.saturating_add(40)).is_some(),
            "Truncated PE TLS directory"
        );
        (
            u32::try_from(
                address
                    .checked_sub(args.image_base)
                    .context("Invalid PE TLS address")?,
            )?,
            40,
        )
    } else {
        (0, 0)
    };
    let load_config = if let Some(address) = named_address(layout, "_load_config_used") {
        let offset = file_offset(&outputs, args.image_base, address)?;
        ensure!(
            image.get(offset..offset.saturating_add(4)).is_some(),
            "Truncated PE load config size"
        );
        let size = u32_at(image, offset);
        ensure!(
            image
                .get(offset..offset.saturating_add(size as usize))
                .is_some(),
            "Truncated PE load config"
        );
        (
            u32::try_from(
                address
                    .checked_sub(args.image_base)
                    .context("Invalid PE load config address")?,
            )?,
            size,
        )
    } else {
        (0, 0)
    };
    let iat_directory = iat_range.map_or((0, 0), |(start, end)| (start, end - start));
    let entry = if args.no_entry {
        0
    } else {
        layout
            .resolved_entry_symbol_address()?
            .context("Missing PE entry point")?
            .checked_sub(args.image_base)
            .context("PE entry point lies below image base")?
    };
    let export_directory = outputs
        .iter()
        .find(|s| s.name == ".edata")
        .map_or((0, 0), |s| (s.rva, s.size));
    let debug_directory = if let Some(pdb) = pdb {
        let address = named_address(layout, "__wild_debug_directory")
            .context("Missing PE debug directory")?;
        let offset = file_offset(&outputs, args.image_base, address)?;
        ensure!(
            image.get(offset..offset + 52).is_some(),
            "Truncated PE CodeView directory"
        );
        put32(image, offset + 24, u32::try_from(offset + 28)?);
        image[offset + 32..offset + 48].copy_from_slice(&pdb.guid);
        (u32::try_from(address - args.image_base)?, 28)
    } else {
        (0, 0)
    };
    let headers = layout
        .section_layouts
        .get(crate::output_section_id::FILE_HEADER)
        .file_size as u32;
    let image_size = outputs
        .iter()
        .map(|s| {
            s.rva
                .checked_add(s.size)?
                .checked_add(4095)
                .map(|end| end & !4095)
        })
        .collect::<Option<Vec<_>>>()
        .context("PE image size overflow")?
        .into_iter()
        .max()
        .unwrap_or(4096);
    let text = outputs.iter().position(|s| s.name == ".text");
    encode_headers(
        image,
        args,
        &outputs,
        entry,
        headers,
        image_size,
        text,
        import_directory,
        exception_directory,
        relocation_directory,
        tls_directory,
        load_config,
        iat_directory,
        export_directory,
        debug_directory,
    )
}

fn relocate(
    layout: &Layout<Coff>,
    object: &ObjectLayout<Coff>,
    index: object::SectionIndex,
    address: u64,
    outputs: &[OutputSection],
    bytes: &mut [u8],
    base_relocations: &mut Vec<(u32, u16)>,
) -> Result {
    let base = layout.args().image_base;
    for rel in object.object.relocations(index, &())?.rel_iter() {
        if rel.kind == 0 {
            continue;
        }
        let symbol = object
            .symbol_id_range
            .input_to_id(object::SymbolIndex(rel.symbol as usize));
        let target = layout
            .merged_symbol_resolution(symbol)
            .with_context(|| format!("Undefined COFF symbol {}", layout.symbol_debug(symbol)))?;
        let va = target.raw_value;
        let absolute = target.flags.is_absolute();
        let pos = rel.offset as usize;
        let width = match rel.kind {
            1 => 8,
            10 => 2,
            _ => 4,
        };
        ensure!(
            pos + width <= bytes.len(),
            "Relocation outside COFF section"
        );
        let place = address + u64::from(rel.offset);
        let section = || -> Option<usize> {
            let canonical = layout.symbol_db.definition(symbol);
            if let crate::grouping::SequencedInput::Object(input) = layout
                .symbol_db
                .file(layout.symbol_db.file_id_for_symbol(canonical))
            {
                let raw = &input.parsed.object.symbols[canonical.to_input(input.symbol_id_range).0];
                if raw.section > 0 {
                    let input_section = input
                        .section_id_range
                        .input_to_id(object::SectionIndex(raw.section as usize - 1));
                    let part = layout.symbol_db.section_part_ids[input_section.as_usize()];
                    let id = layout
                        .output_sections
                        .primary_output_section(part.output_section_id::<Coff>());
                    outputs.iter().position(|s| s.id == id)
                } else if raw.as_common().is_some() {
                    outputs.iter().position(|s| {
                        s.id == crate::output_section_id::OutputSectionId::from_u32(3)
                    })
                } else {
                    None
                }
            } else {
                None
            }
        };
        match rel.kind {
            1 => {
                put64(bytes, pos, u64_at(bytes, pos).wrapping_add(va));
                if !absolute {
                    base_relocations.push(((place - base) as u32, 10));
                }
            }
            2 => {
                let value = i128::from(va) + i128::from(u32_at(bytes, pos) as i32);
                put32(bytes, pos, u32::try_from(value).context("ADDR32 overflow")?);
                if !absolute {
                    base_relocations.push(((place - base) as u32, 3));
                }
            }
            3 => {
                let value =
                    i128::from(va) - i128::from(base) + i128::from(u32_at(bytes, pos) as i32);
                put32(
                    bytes,
                    pos,
                    u32::try_from(value).with_context(|| {
                        format!(
                            "ADDR32NB overflow for {}: VA {va:#x}",
                            layout.symbol_debug(symbol)
                        )
                    })?,
                );
            }
            4..=9 => {
                let value = i128::from(va) + i128::from(u32_at(bytes, pos) as i32)
                    - i128::from(place + 4 + u64::from(rel.kind - 4));
                put32(
                    bytes,
                    pos,
                    i32::try_from(value).with_context(|| {
                        format!(
                            "REL32 overflow for {}: VA {va:#x}, place {place:#x}",
                            layout.symbol_debug(symbol)
                        )
                    })? as u32,
                );
            }
            10 => {
                let s = section().context("SECTION relocation to unallocated symbol")?;
                put16(
                    bytes,
                    pos,
                    u16::try_from(u16_at(bytes, pos) as usize + s + 1)?,
                );
            }
            11 => {
                let s = section().context("SECREL relocation to unallocated symbol")?;
                let offset = va - base - u64::from(outputs[s].rva);
                put32(
                    bytes,
                    pos,
                    u32::try_from(i128::from(offset) + i128::from(u32_at(bytes, pos) as i32))
                        .context("SECREL overflow")?,
                );
            }
            kind => bail!("Unsupported x64 COFF relocation {kind:#x}"),
        }
    }
    Ok(())
}
