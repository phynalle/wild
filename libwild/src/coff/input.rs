use crate::bail;
use crate::ensure;
use crate::error::Context as _;
use crate::error::Result;
use object::LittleEndian as LE;
use object::Object as _;
use object::ObjectSection as _;
use object::pe;
use object::read::coff::CoffFile;
use object::read::coff::CoffHeader;
use object::read::coff::ImportFile;
use object::read::coff::ImportName;
use object::read::coff::ImportType;
use object::read::coff::Symbol as _;
use std::num::NonZeroU32;
use std::ops::Range;

#[derive(Clone, Copy, Debug)]
pub(super) struct Reloc {
    pub offset: u32,
    pub symbol: usize,
    pub kind: u16,
}

impl Reloc {
    pub fn read(bytes: &[u8]) -> Self {
        Self {
            offset: u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            symbol: u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize,
            kind: u16::from_le_bytes(bytes[8..10].try_into().unwrap()),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ByteRange {
    pub start: u32,
    pub end: u32,
}

impl ByteRange {
    pub fn range(self) -> Range<usize> {
        self.start as usize..self.end as usize
    }
    pub fn len(self) -> usize {
        (self.end - self.start) as usize
    }
    pub fn is_empty(self) -> bool {
        self.start == self.end
    }
}

fn byte_range(data: &[u8], bytes: &[u8]) -> ByteRange {
    if bytes.is_empty() {
        return ByteRange::default();
    }
    let start = bytes.as_ptr() as usize - data.as_ptr() as usize;
    assert!(start <= data.len() && bytes.len() <= data.len() - start);
    ByteRange {
        start: start.try_into().unwrap(),
        end: (start + bytes.len()).try_into().unwrap(),
    }
}

#[derive(Debug)]
pub(super) struct Section {
    pub name: ByteRange,
    pub data: ByteRange,
    pub size: u32,
    pub align: u32,
    pub flags: u32,
    pub relocs: ByteRange,
    pub selection: u8,
    pub parent: Option<u32>,
    pub key_symbol: Option<u32>,
    pub anchor_symbol: Option<u32>,
    pub excluded: bool,
    pub tls: bool,
    pub crt: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Symbol {
    pub name: ByteRange,
    pub section: i32,
    pub value: u32,
    pub class: u8,
    pub weak: Option<(NonZeroU32, u32)>,
}

impl Symbol {
    pub fn weak(&self) -> Option<(usize, u32)> {
        self.weak
            .map(|(index, search)| ((index.get() - 1) as usize, search))
    }
}

#[derive(Debug, Default)]
pub(super) struct Object {
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub directives: Vec<String>,
    pub child_offsets: Vec<usize>,
    pub children: Vec<usize>,
}

#[derive(Clone, Debug)]
pub(crate) struct Import {
    pub symbol: String,
    pub dll: String,
    pub name: Option<String>,
    pub ordinal: u16,
    pub code: bool,
}

pub(super) enum Parsed {
    Object(Object),
    Import(Import),
    Metadata,
}

pub(super) fn parse(data: &[u8], name: String) -> Result<Parsed> {
    // Rust archive metadata is not a linkable object.
    if name.ends_with(".rmeta") || data.starts_with(b"rust") {
        return Ok(Parsed::Metadata);
    }
    let kind = kind(data).with_context(|| format!("Invalid COFF input {name}"))?;
    match kind {
        object::FileKind::Coff => {
            parse_object::<pe::ImageFileHeader>(CoffFile::parse(data)?, data, name)
                .map(Parsed::Object)
        }
        object::FileKind::CoffBig => {
            parse_object(object::read::coff::CoffBigFile::parse(data)?, data, name)
                .map(Parsed::Object)
        }
        object::FileKind::CoffImport => {
            let file = ImportFile::parse(data)?;
            ensure!(
                file.architecture() == object::Architecture::X86_64,
                "Non-x64 import {name}"
            );
            let (import, ordinal) = match file.import() {
                ImportName::Name(n) => (Some(std::str::from_utf8(n)?.to_owned()), 0),
                ImportName::Ordinal(n) => (None, n),
            };
            Ok(Parsed::Import(Import {
                symbol: std::str::from_utf8(file.symbol())?.to_owned(),
                dll: std::str::from_utf8(file.dll())?.to_owned(),
                name: import,
                ordinal,
                code: file.import_type() == ImportType::Code,
            }))
        }
        other => bail!("Unsupported COFF input format {other:?} in {name}"),
    }
}

fn parse_object<'a, C: CoffHeader>(
    file: CoffFile<'a, &'a [u8], C>,
    data: &'a [u8],
    name: String,
) -> Result<Object> {
    ensure!(
        data.len() <= u32::MAX as usize,
        "COFF object exceeds 4 GiB: {name}"
    );
    ensure!(
        file.architecture() == object::Architecture::X86_64
            || file.coff_header().machine() == pe::IMAGE_FILE_MACHINE_UNKNOWN,
        "Non-x64 object {name}"
    );
    let mut sections = Vec::new();
    let mut directives = Vec::new();
    for section in file.sections() {
        let header = section.coff_section();
        let section_name = section.name()?;
        let flags = header.characteristics.get(LE).0;
        let bytes = section.data()?;
        if section_name == ".drectve" {
            directives.extend(crate::args::coff::split_windows_args(
                std::str::from_utf8(bytes)?.trim_matches('\0'),
            )?);
        }
        sections.push(Section {
            name: byte_range(data, section_name.as_bytes()),
            size: section.size() as u32,
            data: byte_range(data, bytes),
            align: section.align() as u32,
            flags,
            relocs: byte_range(
                data,
                object::pod::bytes_of_slice(section.coff_relocations()?),
            ),
            selection: 0,
            parent: None,
            key_symbol: None,
            anchor_symbol: None,
            excluded: flags & 0x02000800 != 0
                || section_name.starts_with(".debug")
                || matches!(section_name, ".drectve" | ".llvm_addrsig"),
            tls: section_name.starts_with(".tls"),
            crt: section_name.starts_with(".CRT$"),
        });
    }
    let table = file.coff_symbol_table();
    let mut symbols = vec![Symbol::default(); table.len()];
    let mut representatives = vec![None; sections.len()];
    for (index, symbol) in table.iter() {
        let symbol_name = symbol.name(table.strings())?;
        std::str::from_utf8(symbol_name)?;
        let s = Symbol {
            name: byte_range(data, symbol_name),
            section: symbol.section_number().0,
            value: symbol.value(),
            class: symbol.storage_class().0,
            weak: if symbol.storage_class() == pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
                && symbol.number_of_aux_symbols() > 0
            {
                let aux = table.aux_weak_external(index)?;
                let fallback = aux.weak_default_sym_index.get(LE);
                ensure!(
                    (fallback as usize) < table.len(),
                    "Invalid weak fallback in {name}"
                );
                Some((
                    NonZeroU32::new(fallback + 1).unwrap(),
                    aux.weak_search_type.get(LE).0,
                ))
            } else {
                None
            },
        };
        ensure!(
            s.section <= sections.len() as i32,
            "Symbol {} has an invalid section in {name}",
            std::str::from_utf8(symbol_name)?
        );
        if s.class == 2 && s.section > 0 && s.value == 0 {
            representatives[s.section as usize - 1].get_or_insert(index.0 as u32);
        }
        if symbol.has_aux_section() && s.section > 0 {
            let aux = table.aux_section(index)?;
            let sec = sections
                .get_mut(s.section as usize - 1)
                .context("Invalid COFF section symbol")?;
            if s.value == 0 {
                sec.anchor_symbol.get_or_insert(index.0 as u32);
            }
            sec.selection = aux.selection.0;
            if sec.selection == 5 {
                let n = u32::from(aux.number.get(LE)) | (u32::from(aux.high_number.get(LE)) << 16);
                ensure!(
                    n > 0 && n as usize <= file.coff_section_table().len(),
                    "Invalid associative COMDAT in {name}"
                );
                sec.parent = Some(n - 1);
            }
        }
        symbols[index.0] = s;
    }
    for symbol in &symbols {
        if let Some((fallback, _)) = symbol.weak() {
            ensure!(
                fallback < symbols.len() && !symbols[fallback].name.is_empty(),
                "Invalid weak fallback in {name}"
            );
            let mut next = fallback;
            let mut depth = 0;
            while let Some((fallback, _)) = symbols[next].weak() {
                depth += 1;
                ensure!(
                    depth < 64,
                    "Weak external cycle or excessive depth in {name}"
                );
                ensure!(
                    fallback < symbols.len() && !symbols[fallback].name.is_empty(),
                    "Invalid weak fallback in {name}"
                );
                next = fallback;
            }
        }
    }
    for section in &sections {
        for raw in data[section.relocs.range()].chunks_exact(10) {
            let reloc = Reloc::read(raw);
            if reloc.kind != 0 {
                ensure!(
                    reloc.symbol < symbols.len() && !symbols[reloc.symbol].name.is_empty(),
                    "Invalid relocation symbol in {name}"
                );
            }
        }
    }
    for (i, section) in sections.iter_mut().enumerate() {
        if section.selection != 0 && section.selection != 5 {
            section.key_symbol = representatives[i];
        }
    }
    let mut child_offsets = vec![0; sections.len() + 1];
    for section in &sections {
        if let Some(parent) = section.parent {
            child_offsets[parent as usize + 1] += 1;
        }
    }
    for i in 1..child_offsets.len() {
        child_offsets[i] += child_offsets[i - 1];
    }
    let mut children = vec![0; *child_offsets.last().unwrap()];
    let mut next_child = child_offsets.clone();
    for (child, section) in sections.iter().enumerate() {
        if let Some(parent) = section.parent {
            let parent = parent as usize;
            children[next_child[parent]] = child;
            next_child[parent] += 1;
        }
    }
    Ok(Object {
        sections,
        symbols,
        directives,
        child_offsets,
        children,
    })
}

pub(super) fn kind(data: &[u8]) -> Result<object::FileKind> {
    if data.len() >= 20 && data[..2] == [0, 0] && data[2..4] != [0xff, 0xff] {
        Ok(object::FileKind::Coff)
    } else {
        Ok(object::FileKind::parse(data)?)
    }
}
