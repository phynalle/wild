//! Export declarations and COFF synthesis consumed by the shared engine.
use crate::args::coff::CoffArgs;
use crate::error::{Context, Result};
use crate::{bail, ensure};
use object::write::{Object, Relocation, Symbol, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationFlags, SectionKind, SymbolFlags, SymbolKind,
    SymbolScope,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Export {
    pub name: String,
    pub target: String,
    pub ordinal: Option<u16>,
    pub data: bool,
    pub noname: bool,
    pub private: bool,
}

pub(super) fn parse_export(text: &str) -> Result<Export> {
    let mut fields = text.split(',');
    let names = fields.next().unwrap_or_default().trim_matches('"');
    let (name, target) = names.split_once('=').unwrap_or((names, names));
    ensure!(
        !name.is_empty() && !target.is_empty() && !names.contains('\0'),
        "Invalid export {text}"
    );
    let mut export = Export {
        name: name.into(),
        target: target.into(),
        ordinal: None,
        data: false,
        noname: false,
        private: false,
    };
    for field in fields {
        match field.to_ascii_uppercase().as_str() {
            "DATA" => export.data = true,
            "NONAME" => export.noname = true,
            "PRIVATE" => export.private = true,
            _ if field.starts_with('@') => {
                let ordinal = field[1..].parse::<u16>()?;
                ensure!(ordinal != 0, "Export ordinal cannot be zero");
                ensure!(
                    export.ordinal.replace(ordinal).is_none(),
                    "Duplicate export ordinal"
                );
            }
            _ => bail!("Unsupported export modifier {field}"),
        }
    }
    ensure!(
        !export.noname || export.ordinal.is_some(),
        "NONAME requires an ordinal"
    );
    Ok(export)
}

pub(super) fn parse_definition(text: &str) -> Result<Vec<Export>> {
    let mut in_exports = false;
    let mut exports = Vec::new();
    for line in text.trim_start_matches('\u{feff}').lines() {
        let line = line.split(';').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }
        let tokens = crate::args::coff::split_windows_args(line)?;
        match tokens[0].to_ascii_uppercase().as_str() {
            "EXPORTS" => {
                in_exports = true;
                if tokens.len() > 1 {
                    exports.push(parse_export(&tokens[1..].join(","))?);
                }
            }
            "LIBRARY" | "NAME" => {
                ensure!(!in_exports, "Definition file header follows exports");
            }
            _ => {
                ensure!(in_exports, "Unsupported definition file statement {line}");
                exports.push(parse_export(&tokens.join(","))?);
            }
        }
    }
    Ok(exports)
}

fn dll_name(args: &CoffArgs) -> Result<&str> {
    args.common
        .output
        .file_name()
        .and_then(|name| name.to_str())
        .context("Invalid DLL output filename")
}

fn ordinals(exports: &[Export]) -> Result<Vec<u16>> {
    let mut used = std::collections::BTreeSet::new();
    for export in exports {
        if let Some(ordinal) = export.ordinal {
            ensure!(used.insert(ordinal), "Duplicate export ordinal {ordinal}");
        }
    }
    let mut next = 1u32;
    exports
        .iter()
        .map(|export| {
            if let Some(ordinal) = export.ordinal {
                return Ok(ordinal);
            }
            while next <= u16::MAX as u32 && used.contains(&(next as u16)) {
                next += 1;
            }
            let ordinal = u16::try_from(next).context("Too many DLL exports")?;
            used.insert(ordinal);
            next += 1;
            Ok(ordinal)
        })
        .collect()
}

pub(super) fn object(args: &CoffArgs, exports: &[Export]) -> Result<Vec<u8>> {
    let ordinals = ordinals(exports)?;
    let low = *ordinals.iter().min().context("Empty export directory")?;
    let high = *ordinals.iter().max().unwrap();
    let named = exports.iter().filter(|e| !e.noname).count();
    let eat = 40;
    let names = eat + (usize::from(high - low) + 1) * 4;
    let ordinal_table = names + named * 4;
    let mut bytes = vec![0u8; ordinal_table + named * 2];
    let dll_offset = bytes.len();
    bytes.extend_from_slice(dll_name(args)?.as_bytes());
    bytes.push(0);
    let mut name_offsets = Vec::new();
    for export in exports {
        if !export.noname {
            name_offsets.push(bytes.len());
            bytes.extend_from_slice(export.name.as_bytes());
            bytes.push(0);
        }
    }
    let put32 = |bytes: &mut [u8], pos: usize, value: u32| {
        bytes[pos..pos + 4].copy_from_slice(&value.to_le_bytes())
    };
    put32(&mut bytes, 16, low.into());
    put32(&mut bytes, 20, u32::from(high - low) + 1);
    put32(&mut bytes, 24, named as u32);
    let mut o = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let section = o.add_section(Vec::new(), b".edata".to_vec(), SectionKind::ReadOnlyData);
    o.append_section_data(section, &bytes, 4);
    let anchor = o.add_symbol(Symbol {
        name: b"__wild_export_directory".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(section),
        flags: SymbolFlags::None,
    });
    let rva = |o: &mut Object, offset: usize, symbol, addend: usize| -> Result {
        o.add_relocation(
            section,
            Relocation {
                offset: offset as u64,
                symbol,
                addend: addend as i64,
                flags: RelocationFlags::Coff {
                    typ: object::pe::IMAGE_REL_AMD64_ADDR32NB,
                },
            },
        )?;
        Ok(())
    };
    for (offset, addend) in [
        (12, dll_offset),
        (28, eat),
        (32, names),
        (36, ordinal_table),
    ] {
        rva(&mut o, offset, anchor, addend)?;
    }
    let mut index = 0;
    for (export, ordinal) in exports.iter().zip(ordinals) {
        let target = o.add_symbol(Symbol {
            name: export.target.as_bytes().to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Unknown,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Undefined,
            flags: SymbolFlags::None,
        });
        rva(&mut o, eat + usize::from(ordinal - low) * 4, target, 0)?;
        if !export.noname {
            rva(&mut o, names + index * 4, anchor, name_offsets[index])?;
            let pos = ordinal_table + index * 2;
            o.section_mut(section).data_mut()[pos..pos + 2]
                .copy_from_slice(&(ordinal - low).to_le_bytes());
            index += 1;
        }
    }
    Ok(o.write()?)
}

fn member(out: &mut Vec<u8>, name: &str, bytes: &[u8]) {
    let header = format!(
        "{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
        0,
        0,
        0,
        "100644",
        bytes.len()
    );
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(bytes);
    if bytes.len() % 2 != 0 {
        out.push(b'\n');
    }
}

pub(super) fn import_library(args: &CoffArgs, exports: &[Export]) -> Result<Vec<u8>> {
    let ordinals = ordinals(exports)?;
    let dll = dll_name(args)?;
    let mut members = Vec::new();
    let mut symbols = Vec::new();
    let stem = std::path::Path::new(dll)
        .file_stem()
        .and_then(|s| s.to_str())
        .context("Invalid DLL name")?;
    let descriptor_name = format!("__IMPORT_DESCRIPTOR_{stem}");
    let thunk_name = format!("\u{7f}{stem}_NULL_THUNK_DATA");
    let new_object = || Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let add_symbol =
        |o: &mut Object, name: &[u8], section: SymbolSection, class: object::pe::SymbolClass| {
            o.add_symbol(Symbol {
                name: name.to_vec(),
                value: 0,
                size: 0,
                kind: SymbolKind::Data,
                scope: SymbolScope::Linkage,
                weak: false,
                section,
                flags: SymbolFlags::Coff {
                    typ: object::pe::SymbolType(0),
                    storage_class: class,
                },
            })
        };
    let mut descriptor = new_object();
    let desc = descriptor.add_section(Vec::new(), b".idata$2".to_vec(), SectionKind::Data);
    descriptor.append_section_data(desc, &[0; 20], 4);
    let names = descriptor.add_section(Vec::new(), b".idata$6".to_vec(), SectionKind::Data);
    descriptor.append_section_data(names, &[dll.as_bytes(), b"\0"].concat(), 2);
    add_symbol(
        &mut descriptor,
        descriptor_name.as_bytes(),
        SymbolSection::Section(desc),
        object::pe::IMAGE_SYM_CLASS_EXTERNAL,
    );
    let name_symbol = add_symbol(
        &mut descriptor,
        b".idata$6",
        SymbolSection::Section(names),
        object::pe::IMAGE_SYM_CLASS_STATIC,
    );
    let ilt = add_symbol(
        &mut descriptor,
        b".idata$4",
        SymbolSection::Undefined,
        object::pe::IMAGE_SYM_CLASS_SECTION,
    );
    let iat = add_symbol(
        &mut descriptor,
        b".idata$5",
        SymbolSection::Undefined,
        object::pe::IMAGE_SYM_CLASS_SECTION,
    );
    for (offset, symbol) in [(0, ilt), (12, name_symbol), (16, iat)] {
        descriptor.add_relocation(
            desc,
            Relocation {
                offset,
                symbol,
                addend: 0,
                flags: RelocationFlags::Coff {
                    typ: object::pe::IMAGE_REL_AMD64_ADDR32NB,
                },
            },
        )?;
    }
    add_symbol(
        &mut descriptor,
        b"__NULL_IMPORT_DESCRIPTOR",
        SymbolSection::Undefined,
        object::pe::IMAGE_SYM_CLASS_EXTERNAL,
    );
    add_symbol(
        &mut descriptor,
        thunk_name.as_bytes(),
        SymbolSection::Undefined,
        object::pe::IMAGE_SYM_CLASS_EXTERNAL,
    );
    symbols.push((descriptor_name, members.len()));
    members.push(descriptor.write()?);
    let mut null = new_object();
    let section = null.add_section(Vec::new(), b".idata$3".to_vec(), SectionKind::Data);
    null.append_section_data(section, &[0; 20], 4);
    add_symbol(
        &mut null,
        b"__NULL_IMPORT_DESCRIPTOR",
        SymbolSection::Section(section),
        object::pe::IMAGE_SYM_CLASS_EXTERNAL,
    );
    symbols.push(("__NULL_IMPORT_DESCRIPTOR".into(), members.len()));
    members.push(null.write()?);
    let mut null = new_object();
    let iat = null.add_section(Vec::new(), b".idata$5".to_vec(), SectionKind::Data);
    null.append_section_data(iat, &[0; 8], 8);
    let ilt = null.add_section(Vec::new(), b".idata$4".to_vec(), SectionKind::Data);
    null.append_section_data(ilt, &[0; 8], 8);
    add_symbol(
        &mut null,
        thunk_name.as_bytes(),
        SymbolSection::Section(iat),
        object::pe::IMAGE_SYM_CLASS_EXTERNAL,
    );
    symbols.push((thunk_name, members.len()));
    members.push(null.write()?);
    for (export, ordinal) in exports.iter().zip(ordinals) {
        if export.private {
            continue;
        }
        let mut payload = Vec::new();
        payload.extend_from_slice(export.name.as_bytes());
        payload.push(0);
        payload.extend_from_slice(dll.as_bytes());
        payload.push(0);
        let mut bytes = vec![0; 20];
        bytes[2..4].copy_from_slice(&0xffffu16.to_le_bytes());
        bytes[6..8].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes[16..18].copy_from_slice(&ordinal.to_le_bytes());
        let flags = u16::from(export.data) | if export.noname { 0 } else { 4 };
        bytes[18..20].copy_from_slice(&flags.to_le_bytes());
        bytes.extend_from_slice(&payload);
        let index = members.len();
        if !export.data {
            symbols.push((export.name.clone(), index));
        }
        symbols.push((format!("__imp_{}", export.name), index));
        members.push(bytes);
    }
    symbols.sort_by(|a, b| a.0.cmp(&b.0));
    let size = 4 + symbols.len() * 4 + symbols.iter().map(|s| s.0.len() + 1).sum::<usize>();
    let mut offset = 8 + 60 + (size + 1) / 2 * 2;
    let offsets: Vec<_> = members
        .iter()
        .map(|bytes| {
            let at = offset;
            offset += 60 + (bytes.len() + 1) / 2 * 2;
            at
        })
        .collect();
    let mut index = Vec::new();
    index.extend_from_slice(&(symbols.len() as u32).to_be_bytes());
    for (_, member) in &symbols {
        index.extend_from_slice(&u32::try_from(offsets[*member])?.to_be_bytes());
    }
    for (name, _) in &symbols {
        index.extend_from_slice(name.as_bytes());
        index.push(0);
    }
    let mut out = b"!<arch>\n".to_vec();
    member(&mut out, "/", &index);
    for bytes in members {
        member(&mut out, "import.obj/", &bytes);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definition_preserves_aliases_data_and_ordinals() {
        let exports = parse_definition("LIBRARY sample\nEXPORTS\n value=internal @7 DATA\n entry @3 NONAME\n hidden PRIVATE ; comment\n").unwrap();
        assert_eq!(exports[0].target, "internal");
        assert!(exports[0].data);
        assert_eq!(ordinals(&exports).unwrap(), [7, 3, 1]);
        assert!(exports[1].noname && exports[2].private);
    }

    #[test]
    fn invalid_exports_are_errors() {
        for text in ["", "a,@0", "a,@1,@2", "a,NONAME", "a,FORWARDER", "a="] {
            assert!(parse_export(text).is_err(), "{text}");
        }
        assert!(ordinals(&[parse_export("a,@1").unwrap(), parse_export("b,@1").unwrap()]).is_err());
        assert!(parse_definition("SECTIONS\n.text READ").is_err());
    }

    #[test]
    fn import_archive_index_contains_descriptors_and_short_imports() {
        let mut args = CoffArgs::default();
        args.common.output = std::sync::Arc::from(std::path::Path::new("sample.dll"));
        let exports = [
            parse_export("function").unwrap(),
            parse_export("value,DATA").unwrap(),
        ];
        let bytes = import_library(&args, &exports).unwrap();
        let archive = object::read::archive::ArchiveFile::parse(bytes.as_slice()).unwrap();
        let symbols: Vec<_> = archive
            .symbols()
            .unwrap()
            .unwrap()
            .map(|s| s.unwrap().name().to_vec())
            .collect();
        for name in [
            "__IMPORT_DESCRIPTOR_sample",
            "__NULL_IMPORT_DESCRIPTOR",
            "__imp_function",
            "__imp_value",
            "function",
        ] {
            assert!(symbols.iter().any(|s| s == name.as_bytes()), "{name}");
        }
        assert!(!symbols.iter().any(|s| s == b"value"));
        assert_eq!(archive.members().count(), 5);
    }
}
