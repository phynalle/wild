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

#[derive(Clone, Debug)]
pub(super) struct Reloc {
    pub offset: u32,
    pub symbol: usize,
    pub kind: u16,
}

#[derive(Debug)]
pub(super) struct Section {
    pub name: String,
    pub data: Vec<u8>,
    pub size: u32,
    pub align: u32,
    pub flags: u32,
    pub relocs: Vec<Reloc>,
    pub selection: u8,
    pub parent: Option<usize>,
    pub key: String,
    pub replacement: Option<(usize, usize)>,
    pub live: bool,
    pub output: usize,
    pub offset: u32,
}

impl Section {
    pub fn excluded(&self) -> bool {
        self.flags & 0x800 != 0
            || self.flags & 0x02000800 != 0
            || self.name.starts_with(".debug")
            || self.name == ".drectve"
            || self.name == ".llvm_addrsig"
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct Symbol {
    pub name: String,
    pub section: i32,
    pub value: u32,
    pub class: u8,
    pub weak: Option<(usize, u32)>,
}

impl Symbol {
    pub fn external(&self) -> bool {
        self.class == 2 || self.class == 105
    }
    pub fn definition(&self) -> bool {
        self.external() && (self.section != 0 || self.value != 0)
    }
}

#[derive(Debug)]
pub(super) struct Object {
    pub name: String,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub directives: Vec<String>,
    pub active: bool,
}

#[derive(Clone, Debug)]
pub(super) struct Import {
    pub symbol: String,
    pub dll: String,
    pub name: Option<String>,
    pub ordinal: u16,
    pub code: bool,
    pub live: bool,
    pub iat: u32,
    pub thunk: u32,
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
    let kind = if data.len() >= 20 && data[..2] == [0, 0] && data[2..4] != [0xff, 0xff] {
        object::FileKind::Coff
    } else {
        object::FileKind::parse(data).with_context(|| format!("Invalid COFF input {name}"))?
    };
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
                live: false,
                iat: 0,
                thunk: 0,
            }))
        }
        other => bail!("Unsupported COFF input format {other:?} in {name}"),
    }
}

fn parse_object<'a, C: CoffHeader>(
    file: CoffFile<'a, &'a [u8], C>,
    _data: &'a [u8],
    name: String,
) -> Result<Object> {
    ensure!(
        file.architecture() == object::Architecture::X86_64
            || file.coff_header().machine() == pe::IMAGE_FILE_MACHINE_UNKNOWN,
        "Non-x64 object {name}"
    );
    let mut sections = Vec::new();
    let mut directives = Vec::new();
    for section in file.sections() {
        let header = section.coff_section();
        let section_name = section.name()?.to_owned();
        let bytes = section.data()?.to_vec();
        if section_name == ".drectve" {
            directives.extend(crate::args::coff::split_windows_args(
                std::str::from_utf8(&bytes)?.trim_matches('\0'),
            )?);
        }
        sections.push(Section {
            name: section_name,
            size: section.size() as u32,
            data: bytes,
            align: section.align() as u32,
            flags: header.characteristics.get(LE).0,
            relocs: section
                .coff_relocations()?
                .iter()
                .map(|r| Reloc {
                    offset: r.virtual_address.get(LE),
                    symbol: r.symbol_table_index.get(LE) as usize,
                    kind: r.typ.get(LE).0,
                })
                .collect(),
            selection: 0,
            parent: None,
            key: String::new(),
            replacement: None,
            live: false,
            output: 0,
            offset: 0,
        });
    }
    let table = file.coff_symbol_table();
    let mut symbols = vec![Symbol::default(); table.len()];
    for (index, symbol) in table.iter() {
        let s = Symbol {
            name: std::str::from_utf8(symbol.name(table.strings())?)?.to_owned(),
            section: symbol.section_number().0,
            value: symbol.value(),
            class: symbol.storage_class().0,
            weak: if symbol.storage_class() == pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
                && symbol.number_of_aux_symbols() > 0
            {
                let aux = table.aux_weak_external(index)?;
                Some((
                    aux.weak_default_sym_index.get(LE) as usize,
                    aux.weak_search_type.get(LE).0,
                ))
            } else {
                None
            },
        };
        ensure!(
            s.section <= sections.len() as i32,
            "Symbol {} has an invalid section in {name}",
            s.name
        );
        if symbol.has_aux_section() && s.section > 0 {
            let aux = table.aux_section(index)?;
            let sec = sections
                .get_mut(s.section as usize - 1)
                .context("Invalid COFF section symbol")?;
            sec.selection = aux.selection.0;
            if sec.selection == 5 {
                let n = u32::from(aux.number.get(LE)) | (u32::from(aux.high_number.get(LE)) << 16);
                ensure!(
                    n > 0 && n as usize <= file.coff_section_table().len(),
                    "Invalid associative COMDAT in {name}"
                );
                sec.parent = Some(n as usize - 1);
            }
        }
        symbols[index.0] = s;
    }
    for symbol in &symbols {
        if let Some((fallback, _)) = symbol.weak {
            ensure!(
                fallback < symbols.len() && !symbols[fallback].name.is_empty(),
                "Invalid weak fallback in {name}"
            );
        }
    }
    for section in &sections {
        for reloc in &section.relocs {
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
            let key = symbols
                .iter()
                .find(|s| s.class == 2 && s.section == i as i32 + 1 && s.value == 0);
            section.key = key.map_or_else(|| format!("@local:{i}"), |s| s.name.clone());
        }
    }
    Ok(Object {
        name,
        sections,
        symbols,
        directives,
        active: false,
    })
}
