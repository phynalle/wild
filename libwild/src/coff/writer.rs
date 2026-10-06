use super::resolve::Resolver;
use super::resolve::Target;
use crate::args::coff::Subsystem;
use crate::bail;
use crate::ensure;
use crate::error::Context as _;
use crate::error::Result;
use crate::fs::FileSystem;
use std::collections::BTreeMap;

struct OutputSection {
    name: String,
    flags: u32,
    size: u32,
    data: Vec<u8>,
    rva: u32,
    raw: u32,
    members: Vec<(String, usize, usize)>,
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

struct Address {
    va: u64,
    section: usize,
    relative: u32,
    absolute: bool,
}

fn address<F: FileSystem>(
    r: &Resolver<'_, F>,
    outputs: &[OutputSection],
    target: Target,
    common: usize,
) -> Result<Address> {
    let base = r.args.image_base;
    match target {
        Target::ImageBase => Ok(Address {
            va: base,
            section: 0,
            relative: 0,
            absolute: false,
        }),
        Target::Import(i, iat) => {
            let imp = &r.imports[i];
            let rva = if iat { imp.iat } else { imp.thunk };
            let section = outputs
                .iter()
                .position(|s| rva >= s.rva && rva < s.rva + s.size)
                .context("Unallocated import")?;
            Ok(Address {
                va: base + rva as u64,
                section,
                relative: rva - outputs[section].rva,
                absolute: false,
            })
        }
        Target::Symbol(o, s) => {
            let symbol = &r.objects[o].symbols[s];
            if symbol.section == -1 {
                return Ok(Address {
                    va: symbol.value as u64,
                    section: 0,
                    relative: symbol.value,
                    absolute: true,
                });
            }
            if symbol.section == 0 {
                let (_, offset) = r
                    .commons
                    .get(&symbol.name)
                    .context("Unallocated common symbol")?;
                return Ok(Address {
                    va: base + (outputs[common].rva + offset) as u64,
                    section: common,
                    relative: *offset,
                    absolute: false,
                });
            }
            ensure!(
                symbol.section > 0,
                "Invalid symbol section for {}",
                symbol.name
            );
            let (o, sec) = r.canonical(o, symbol.section as usize - 1);
            let sec = &r.objects[o].sections[sec];
            ensure!(
                sec.live,
                "Reference to discarded section {} in {}",
                sec.name,
                r.objects[o].name
            );
            let relative = sec.offset + symbol.value;
            Ok(Address {
                va: base + (outputs[sec.output].rva + relative) as u64,
                section: sec.output,
                relative,
                absolute: false,
            })
        }
    }
}

pub(super) fn write<F: FileSystem>(r: &mut Resolver<'_, F>) -> Result<Vec<u8>> {
    ensure!(
        r.args.image_base % 65536 == 0,
        "PE image base must be aligned to 64 KiB"
    );
    let mut groups: BTreeMap<String, Vec<(String, usize, usize)>> = BTreeMap::new();
    for (o, object) in r.objects.iter().enumerate().filter(|(_, o)| o.active) {
        for (s, sec) in object.sections.iter().enumerate().filter(|(_, s)| s.live) {
            let mut name = sec.name.split('$').next().unwrap().to_owned();
            let mut depth = 0;
            while let Some(to) = r.merges.get(&name) {
                name = to.clone();
                depth += 1;
                ensure!(depth < 32, "Section merge cycle");
            }
            ensure!(name.len() <= 8, "PE section name exceeds 8 bytes: {name}");
            groups
                .entry(name)
                .or_default()
                .push((sec.name.clone(), o, s));
        }
    }
    if !r.commons.is_empty() {
        groups.entry(".bss".into()).or_default();
    }
    groups.retain(|name, members| {
        (name == ".bss" && !r.commons.is_empty())
            || members
                .iter()
                .any(|(_, o, s)| r.objects[*o].sections[*s].size != 0)
    });
    if r.imports.iter().any(|i| i.live) {
        groups.entry(".idata".into()).or_default();
        groups.entry(".text".into()).or_default();
    }
    groups.entry(".reloc".into()).or_default();
    let mut outputs = Vec::new();
    let mut groups: Vec<_> = groups.into_iter().collect();
    groups.sort_by_key(|(name, _)| name == ".reloc");
    for (name, mut members) in groups {
        members.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
        let index = outputs.len();
        let mut size: u32 = 0;
        let mut flags = 0;
        for (_, o, s) in &members {
            let sec = &mut r.objects[*o].sections[*s];
            size = align(size, sec.align.max(1));
            sec.output = index;
            sec.offset = size;
            size = size
                .checked_add(sec.size)
                .context("PE section exceeds 4 GiB")?;
            flags |= sec.flags & 0xe00000e0;
        }
        if flags == 0 {
            flags = match name.as_str() {
                ".text" => 0x60000020,
                ".bss" => 0xc0000080,
                ".idata" => 0xc0000040,
                ".reloc" => 0x42000040,
                _ => 0x40000040,
            };
        }
        if let Some(attrs) = r.section_flags.get(&name) {
            flags &= !0xe0000000;
            for attr in attrs.chars() {
                flags |= match attr {
                    'E' => 0x20000000,
                    'R' => 0x40000000,
                    'W' => 0x80000000,
                    'D' => 0x02000000,
                    'S' => 0x10000000,
                    'K' => 0x04000000,
                    'P' => 0x08000000,
                    _ => bail!("Unsupported /SECTION attribute {attr}"),
                };
            }
        }
        outputs.push(OutputSection {
            name,
            flags,
            size,
            data: if flags & 0x60 != 0 {
                vec![0; size as usize]
            } else {
                Vec::new()
            },
            rva: 0,
            raw: 0,
            members,
        });
    }
    let common = outputs.iter().position(|s| s.name == ".bss").unwrap_or(0);
    for (size, offset) in r.commons.values_mut() {
        let sec = &mut outputs[common];
        sec.size = align(sec.size, 16);
        *offset = sec.size;
        sec.size += *size;
    }
    for out in &mut outputs {
        for (_, o, s) in &out.members {
            let sec = &r.objects[*o].sections[*s];
            if !sec.data.is_empty() {
                let end = sec.offset as usize + sec.data.len();
                if out.data.len() < end {
                    out.data.resize(end, 0);
                }
                out.data[sec.offset as usize..end].copy_from_slice(&sec.data);
            }
        }
    }
    let mut imports: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, imp) in r.imports.iter().enumerate().filter(|(_, i)| i.live) {
        imports
            .entry(imp.dll.to_ascii_lowercase())
            .or_default()
            .push(i);
    }
    let idata = outputs.iter().position(|s| s.name == ".idata");
    let text = outputs.iter().position(|s| s.name == ".text");
    let mut fixups: Vec<(u32, u32, bool)> = Vec::new();
    let mut import_directory = (0, 0);
    let mut iat_directory = (0, 0);
    if !imports.is_empty() {
        let sec = &mut outputs[idata.unwrap()];
        let start = align(sec.size, 8);
        let descriptors = (imports.len() as u32 + 1) * 20;
        let iat_start = align(start + descriptors, 8);
        let iat_size = imports
            .values()
            .map(|s| (s.len() as u32 + 1) * 8)
            .sum::<u32>();
        sec.data.resize((iat_start + iat_size) as usize, 0);
        iat_directory = (iat_start, iat_size);
        let mut iat_cursor = iat_start;
        import_directory = (start, descriptors);
        for (d, (dll, symbols)) in imports.iter().enumerate() {
            let descriptor = start + d as u32 * 20;
            let ilt = align(sec.data.len() as u32, 8);
            let iat = iat_cursor;
            iat_cursor += (symbols.len() as u32 + 1) * 8;
            sec.data
                .resize((ilt + (symbols.len() as u32 + 1) * 8) as usize, 0);
            let dll_offset = sec.data.len() as u32;
            sec.data.extend_from_slice(dll.as_bytes());
            sec.data.push(0);
            fixups.extend([
                (descriptor, ilt, false),
                (descriptor + 12, dll_offset, false),
                (descriptor + 16, iat, false),
            ]);
            for (slot, i) in symbols.iter().enumerate() {
                let imp = &mut r.imports[*i];
                imp.iat = iat + slot as u32 * 8;
                let entry = if let Some(name) = &imp.name {
                    let offset = align(sec.data.len() as u32, 2);
                    sec.data.resize(offset as usize + 2, 0);
                    sec.data.extend_from_slice(name.as_bytes());
                    sec.data.push(0);
                    fixups.extend([
                        (ilt + slot as u32 * 8, offset, true),
                        (iat + slot as u32 * 8, offset, true),
                    ]);
                    0
                } else {
                    (1u64 << 63) | u64::from(imp.ordinal)
                };
                put64(&mut sec.data, (ilt + slot as u32 * 8) as usize, entry);
                put64(&mut sec.data, imp.iat as usize, entry);
            }
        }
        sec.size = sec.data.len() as u32;
        let sec = &mut outputs[text.unwrap()];
        for imp in r.imports.iter_mut().filter(|i| i.live && i.code) {
            sec.size = align(sec.size, 16);
            imp.thunk = sec.size;
            sec.size += 6;
            sec.data.resize(sec.size as usize, 0xcc);
        }
    }
    let headers = align(0x80 + 4 + 20 + 240 + outputs.len() as u32 * 40, 512);
    let mut rva = align(headers, 4096);
    for out in &mut outputs {
        out.rva = rva;
        rva = align(
            rva.checked_add(out.size.max(1))
                .context("PE image exceeds 4 GiB")?,
            4096,
        );
    }
    if !imports.is_empty() {
        let idata_rva = outputs[idata.unwrap()].rva;
        for (offset, value, wide) in fixups {
            let bytes = &mut outputs[idata.unwrap()].data;
            if wide {
                put64(bytes, offset as usize, (idata_rva + value) as u64);
            } else {
                put32(bytes, offset as usize, idata_rva + value);
            }
        }
        import_directory.0 += idata_rva;
        iat_directory.0 += idata_rva;
        let sec = &mut outputs[text.unwrap()];
        for imp in r.imports.iter_mut().filter(|i| i.live) {
            imp.iat += idata_rva;
            if imp.code {
                let offset = imp.thunk as usize;
                imp.thunk += sec.rva;
                sec.data[offset..offset + 2].copy_from_slice(&[0xff, 0x25]);
                let delta = i64::from(imp.iat) - i64::from(imp.thunk + 6);
                put32(
                    &mut sec.data,
                    offset + 2,
                    i32::try_from(delta)?.cast_unsigned(),
                );
            }
        }
    }
    let mut base_relocations = Vec::new();
    for (o, object) in r.objects.iter().enumerate().filter(|(_, o)| o.active) {
        for sec in object.sections.iter().filter(|s| s.live) {
            for rel in &sec.relocs {
                if rel.kind == 0 {
                    continue;
                }
                let target = address(r, &outputs, r.target(o, rel.symbol)?, common)?;
                let pos = sec.offset as usize + rel.offset as usize;
                let place = outputs[sec.output].rva + sec.offset + rel.offset;
                let bytes = &mut outputs[sec.output].data;
                let width = match rel.kind {
                    1 => 8,
                    10 => 2,
                    _ => 4,
                };
                ensure!(
                    pos + width <= sec.offset as usize + sec.size as usize
                        && pos + width <= bytes.len(),
                    "Relocation outside {} in {}",
                    sec.name,
                    object.name
                );
                match rel.kind {
                    1 => {
                        let value = u64_at(bytes, pos).wrapping_add(target.va);
                        put64(bytes, pos, value);
                        if !target.absolute {
                            base_relocations.push((place, 10u16));
                        }
                    }
                    2 => {
                        let value = i128::from(u32_at(bytes, pos) as i32) + i128::from(target.va);
                        put32(
                            bytes,
                            pos,
                            u32::try_from(value).with_context(|| {
                                format!(
                                    "ADDR32 overflow: {} section {} symbol {} value {value:#x}",
                                    object.name, sec.name, object.symbols[rel.symbol].name
                                )
                            })?,
                        );
                        if !target.absolute {
                            base_relocations.push((place, 3u16));
                        }
                    }
                    3 => {
                        let addend = u32_at(bytes, pos);
                        let value = i128::from(target.va) - i128::from(r.args.image_base)
                            + i128::from(addend as i32);
                        put32(bytes, pos, u32::try_from(value).with_context(|| format!("ADDR32NB overflow: {} section {} symbol {} target {:#x} addend {addend:#x}", object.name, sec.name, object.symbols[rel.symbol].name, target.va))?);
                    }
                    4..=9 => {
                        let addend = u32_at(bytes, pos) as i32;
                        let delta = i128::from(target.va) + i128::from(addend)
                            - i128::from(
                                r.args.image_base + place as u64 + 4 + u64::from(rel.kind - 4),
                            );
                        put32(
                            bytes,
                            pos,
                            i32::try_from(delta)
                                .with_context(|| format!("REL32 overflow in {}", object.name))?
                                .cast_unsigned(),
                        );
                    }
                    10 => {
                        let value = u16_at(bytes, pos) as usize + target.section + 1;
                        put16(bytes, pos, u16::try_from(value)?);
                    }
                    11 => {
                        let value =
                            i64::from(u32_at(bytes, pos) as i32) + i64::from(target.relative);
                        put32(bytes, pos, u32::try_from(value).context("SECREL overflow")?);
                    }
                    kind => bail!(
                        "Unsupported x64 COFF relocation {kind:#x} in {}",
                        object.name
                    ),
                }
            }
        }
    }
    let mut exception_directory = (0, 0);
    if let Some(i) = outputs.iter().position(|s| s.name == ".pdata") {
        let out = &mut outputs[i];
        ensure!(out.data.len() % 12 == 0, "Invalid x64 .pdata length");
        let mut records: Vec<[u8; 12]> = out
            .data
            .chunks_exact(12)
            .map(|b| b.try_into().unwrap())
            .filter(|b: &[u8; 12]| u32_at(b, 0) != 0)
            .collect();
        records.sort_by_key(|b| u32_at(b, 0));
        out.data = records.into_iter().flatten().collect();
        out.size = out.data.len() as u32;
        exception_directory = (out.rva, out.size);
    }
    base_relocations.sort_unstable();
    base_relocations.dedup();
    let reloc_output = outputs.iter().position(|s| s.name == ".reloc").unwrap();
    let reloc = &mut outputs[reloc_output];
    let mut cursor = 0;
    while cursor < base_relocations.len() {
        let page = base_relocations[cursor].0 & !4095;
        let start = reloc.data.len();
        reloc.data.resize(start + 8, 0);
        while cursor < base_relocations.len() && base_relocations[cursor].0 & !4095 == page {
            let (rva, kind) = base_relocations[cursor];
            reloc
                .data
                .extend_from_slice(&((kind << 12) | (rva & 4095) as u16).to_le_bytes());
            cursor += 1;
        }
        while reloc.data.len() % 4 != 0 {
            reloc.data.push(0);
        }
        let size = (reloc.data.len() - start) as u32;
        put32(&mut reloc.data, start, page);
        put32(&mut reloc.data, start + 4, size);
    }
    reloc.size = reloc.data.len() as u32;
    let end = outputs
        .iter()
        .filter(|s| s.name != ".reloc")
        .map(|s| align(s.rva + s.size.max(1), 4096))
        .max()
        .unwrap_or(4096);
    outputs[reloc_output].rva = end;
    let image_size = align(end + outputs[reloc_output].size, 4096);
    let relocation_directory = (end, outputs[reloc_output].size);
    let entry = address(
        r,
        &outputs,
        r.named_target(&r.entry, 0)?
            .context("Missing PE entry point")?,
        common,
    )?
    .va - r.args.image_base;
    let mut tls_directory = (0, 0);
    if let Some(t) = r.named_target("_tls_used", 0)? {
        tls_directory = (
            (address(r, &outputs, t, common)?.va - r.args.image_base) as u32,
            40,
        );
    }
    let mut load_config = (0, 0);
    if let Some(t) = r.named_target("_load_config_used", 0)? {
        let a = address(r, &outputs, t, common)?;
        let size = u32_at(&outputs[a.section].data, a.relative as usize);
        load_config = ((a.va - r.args.image_base) as u32, size);
    }
    if imports.is_empty() {
        if let Some(i) = idata {
            let sec = &outputs[i];
            let descriptors: Vec<_> = sec
                .members
                .iter()
                .filter(|(n, _, _)| n == ".idata$2")
                .collect();
            if let Some((_, o, s)) = descriptors.first() {
                import_directory = (
                    sec.rva + r.objects[*o].sections[*s].offset,
                    (descriptors.len() as u32 + 1) * 20,
                );
            }
        }
    }
    if outputs
        .last()
        .is_some_and(|s| s.name == ".reloc" && s.size == 0)
    {
        outputs.pop();
    }
    let mut raw = headers;
    for out in &mut outputs {
        if !out.data.is_empty() {
            out.raw = raw;
            raw += align(out.data.len() as u32, 512);
        }
    }
    let mut image = vec![0u8; raw as usize];
    ensure!(
        outputs.len() <= 96,
        "Windows PE loader supports at most 96 sections"
    );
    image[..2].copy_from_slice(b"MZ");
    put16(&mut image, 2, 0x90);
    put16(&mut image, 4, 3);
    put16(&mut image, 8, 4);
    put16(&mut image, 12, 0xffff);
    put16(&mut image, 16, 0xb8);
    put16(&mut image, 24, 0x40);
    put32(&mut image, 0x3c, 0x80);
    image[0x80..0x84].copy_from_slice(b"PE\0\0");
    put16(&mut image, 0x84, 0x8664);
    put16(&mut image, 0x86, outputs.len() as u16);
    put16(&mut image, 0x94, 240);
    put16(
        &mut image,
        0x96,
        2 | if r.args.large_address_aware { 0x20 } else { 0 },
    );
    let opt = 0x98;
    put16(&mut image, opt, 0x20b);
    image[opt + 2] = 1;
    put32(
        &mut image,
        opt + 4,
        outputs
            .iter()
            .filter(|s| s.flags & 0x20 != 0)
            .map(|s| align(s.data.len() as u32, 512))
            .sum(),
    );
    put32(
        &mut image,
        opt + 8,
        outputs
            .iter()
            .filter(|s| s.flags & 0x40 != 0)
            .map(|s| align(s.data.len() as u32, 512))
            .sum(),
    );
    put32(
        &mut image,
        opt + 12,
        outputs
            .iter()
            .filter(|s| s.flags & 0x80 != 0)
            .map(|s| s.size)
            .sum(),
    );
    put32(&mut image, opt + 16, u32::try_from(entry)?);
    put32(&mut image, opt + 20, text.map_or(0, |i| outputs[i].rva));
    put64(&mut image, opt + 24, r.args.image_base);
    put32(&mut image, opt + 32, 4096);
    put32(&mut image, opt + 36, 512);
    put16(&mut image, opt + 40, 6);
    put16(&mut image, opt + 48, r.args.subsystem_version.0);
    put16(&mut image, opt + 50, r.args.subsystem_version.1);
    put32(&mut image, opt + 56, image_size);
    put32(&mut image, opt + 60, headers);
    put16(
        &mut image,
        opt + 68,
        if r.args.subsystem == Some(Subsystem::Windows) {
            2
        } else {
            3
        },
    );
    put16(
        &mut image,
        opt + 70,
        0x8000
            | if r.args.nx_compat { 0x100 } else { 0 }
            | if r.args.dynamic_base { 0x40 } else { 0 }
            | if r.args.dynamic_base && r.args.high_entropy_va {
                0x20
            } else {
                0
            },
    );
    put64(&mut image, opt + 72, r.args.stack.0);
    put64(&mut image, opt + 80, r.args.stack.1);
    put64(&mut image, opt + 88, r.args.heap.0);
    put64(&mut image, opt + 96, r.args.heap.1);
    put32(&mut image, opt + 108, 16);
    for (i, (rva, size)) in [
        (1, import_directory),
        (3, exception_directory),
        (5, relocation_directory),
        (9, tls_directory),
        (10, load_config),
        (12, iat_directory),
    ] {
        if size > 0 {
            put32(&mut image, opt + 112 + i * 8, rva);
            put32(&mut image, opt + 116 + i * 8, size);
        }
    }
    for (i, out) in outputs.iter().enumerate() {
        let sh = opt + 240 + i * 40;
        image[sh..sh + out.name.len()].copy_from_slice(out.name.as_bytes());
        put32(&mut image, sh + 8, out.size);
        put32(&mut image, sh + 12, out.rva);
        put32(&mut image, sh + 16, align(out.data.len() as u32, 512));
        put32(&mut image, sh + 20, out.raw);
        put32(&mut image, sh + 36, out.flags);
        if !out.data.is_empty() {
            image[out.raw as usize..out.raw as usize + out.data.len()].copy_from_slice(&out.data);
        }
    }
    Ok(image)
}
