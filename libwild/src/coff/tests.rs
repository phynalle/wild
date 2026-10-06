use super::*;
use crate::args::Input;
use crate::args::InputSpec;
use crate::args::Modifiers;
use object::Architecture;
use object::BinaryFormat;
use object::ComdatKind;
use object::Endianness;
use object::Object as _;
use object::ObjectSection as _;
use object::RelocationFlags;
use object::SectionKind;
use object::SymbolFlags;
use object::SymbolKind;
use object::SymbolScope;
use object::write::Comdat;
use object::write::Object;
use object::write::Relocation;
use object::write::Symbol;
use object::write::SymbolSection;
use std::path::Path;
use std::sync::Arc;

fn object(name: &str, bytes: &[u8], selection: Option<ComdatKind>) -> Vec<u8> {
    symbol_object(name, bytes, selection, false)
}

fn symbol_object(name: &str, bytes: &[u8], selection: Option<ComdatKind>, weak: bool) -> Vec<u8> {
    let mut o = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let section = o.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    o.append_section_data(section, bytes, 16);
    o.section_symbol(section);
    let symbol = o.add_symbol(Symbol {
        name: name.as_bytes().to_vec(),
        value: 0,
        size: bytes.len() as u64,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak,
        section: SymbolSection::Section(section),
        flags: SymbolFlags::None,
    });
    if let Some(kind) = selection {
        o.add_comdat(Comdat {
            kind,
            symbol,
            sections: vec![section],
        });
    }
    o.write().unwrap()
}

fn link_objects(objects: &[Vec<u8>], extra: impl FnOnce(&mut CoffArgs)) -> Result<Vec<u8>> {
    let temp = tempfile::tempdir().unwrap();
    let mut args = CoffArgs::default();
    args.entry = Some("entry".into());
    args.common.output = Arc::from(temp.path().join("image.exe"));
    for (i, bytes) in objects.iter().enumerate() {
        let path = temp.path().join(format!("{i}.obj"));
        std::fs::write(&path, bytes).unwrap();
        args.common.inputs.push(Input {
            spec: InputSpec::File(path.into()),
            modifiers: Modifiers::default(),
            search_first: None,
        });
    }
    extra(&mut args);
    link(&crate::OsFileSystem, &args)?;
    Ok(std::fs::read(&args.common.output).unwrap())
}

#[test]
fn pe_entry_and_section_permissions() {
    let bytes = link_objects(&[object("entry", &[0xc3], None)], |_| {}).unwrap();
    let pe = object::read::pe::PeFile64::parse(&*bytes).unwrap();
    let text = pe.section_by_name(".text").unwrap();
    assert_eq!(pe.entry(), text.address());
    assert_eq!(text.data().unwrap()[0], 0xc3);
    assert!(
        matches!(text.flags(), object::SectionFlags::Coff { characteristics } if characteristics.contains(object::pe::IMAGE_SCN_MEM_EXECUTE))
    );
}

#[test]
fn duplicate_strong_definitions_fail() {
    let err = link_objects(
        &[
            object("entry", &[0xc3], None),
            object("entry", &[0xc3], None),
        ],
        |_| {},
    )
    .unwrap_err();
    assert!(err.to_string().contains("Duplicate symbol entry"));
}

#[test]
fn comdat_any_selects_first() {
    let bytes = link_objects(
        &[
            object("entry", &[0xc3], Some(ComdatKind::Any)),
            object("entry", &[0xcc], Some(ComdatKind::Any)),
        ],
        |_| {},
    )
    .unwrap();
    let pe = object::read::pe::PeFile64::parse(&*bytes).unwrap();
    assert_eq!(
        pe.section_by_name(".text").unwrap().data().unwrap()[0],
        0xc3
    );
}

#[test]
fn comdat_size_mismatch_fails() {
    let err = link_objects(
        &[
            object("entry", &[0xc3], Some(ComdatKind::SameSize)),
            object("entry", &[0x90, 0xc3], Some(ComdatKind::SameSize)),
        ],
        |_| {},
    )
    .unwrap_err();
    assert!(err.to_string().contains("size mismatch"));
}

#[test]
fn dead_comdat_does_not_require_undefined_symbol() {
    let mut dead = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let section = dead.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    dead.append_section_data(section, &[0xe8, 0, 0, 0, 0, 0xc3], 16);
    dead.section_symbol(section);
    let symbol = dead.add_symbol(Symbol {
        name: b"unused".to_vec(),
        value: 0,
        size: 6,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(section),
        flags: SymbolFlags::None,
    });
    dead.add_comdat(Comdat {
        kind: ComdatKind::Any,
        symbol,
        sections: vec![section],
    });
    let undefined = dead.add_symbol(Symbol {
        name: b"missing".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });
    dead.add_relocation(
        section,
        Relocation {
            offset: 1,
            symbol: undefined,
            addend: 0,
            flags: RelocationFlags::Coff {
                typ: object::pe::IMAGE_REL_AMD64_REL32,
            },
        },
    )
    .unwrap();
    let dead = dead.write().unwrap();
    assert!(link_objects(&[object("entry", &[0xc3], None), dead.clone()], |_| {}).is_ok());
    let error =
        link_objects(&[object("entry", &[0xc3], None), dead], |a| a.gc = false).unwrap_err();
    assert!(error.to_string().contains("Undefined symbol missing"));
}

#[test]
fn mismatch_directive_is_diagnosed() {
    let error = link_objects(&[object("entry", &[0xc3], None)], |a| {
        a.directives.extend([
            "/FAILIFMISMATCH:runtime=A".into(),
            "/FAILIFMISMATCH:runtime=B".into(),
        ])
    })
    .unwrap_err();
    assert!(error.to_string().contains("/FAILIFMISMATCH runtime"));
}

#[test]
fn windows_paths_and_attached_quotes_survive() {
    let args = crate::args::coff::split_windows_args(
        r#"/LIBPATH:"C:\Program Files\SDK\lib" "C:\obj\a.obj" "" "a\"b""#,
    )
    .unwrap();
    assert_eq!(
        args,
        [
            r"/LIBPATH:C:\Program Files\SDK\lib",
            r"C:\obj\a.obj",
            "",
            "a\"b"
        ]
    );
}

#[test]
fn utf16_response_file() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("link.rsp");
    let input = "/OUT:\"C:\\objects\\hello.exe\" hello.obj";
    let bytes: Vec<_> = [0xfeffu16]
        .into_iter()
        .chain(input.encode_utf16())
        .flat_map(u16::to_le_bytes)
        .collect();
    std::fs::write(&path, bytes).unwrap();
    assert_eq!(
        crate::args::coff::read_response_file(Path::new(&path)).unwrap(),
        [r"/OUT:C:\objects\hello.exe", "hello.obj"]
    );
}

#[test]
fn unused_archive_member_does_not_override_entry() {
    let member = object("entry", &[0xcc], None);
    let mut builder = ar::Builder::new(Vec::new());
    builder
        .append(
            &ar::Header::new(b"unused.obj".to_vec(), member.len() as u64),
            &*member,
        )
        .unwrap();
    let archive = builder.into_inner().unwrap();
    let bytes = link_objects(&[object("entry", &[0xc3], None), archive.clone()], |_| {}).unwrap();
    let pe = object::read::pe::PeFile64::parse(&*bytes).unwrap();
    assert_eq!(
        pe.section_by_name(".text").unwrap().data().unwrap()[0],
        0xc3
    );
    let error = link_objects(&[object("entry", &[0xc3], None), archive], |a| {
        a.directives.push("/WHOLEARCHIVE".into())
    })
    .unwrap_err();
    assert!(error.to_string().contains("Duplicate symbol entry"));
}

#[test]
fn security_options_change_pe_header() {
    let bytes = link_objects(&[object("entry", &[0xc3], None)], |a| {
        a.nx_compat = false;
        a.dynamic_base = false;
        a.large_address_aware = false;
        a.subsystem_version = (10, 0);
    })
    .unwrap();
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let characteristics = u16::from_le_bytes(bytes[pe + 22..pe + 24].try_into().unwrap());
    let dll = u16::from_le_bytes(bytes[pe + 24 + 70..pe + 24 + 72].try_into().unwrap());
    assert_eq!(characteristics & 0x20, 0);
    assert_eq!(dll & 0x160, 0);
    assert_eq!(
        u16::from_le_bytes(bytes[pe + 24 + 48..pe + 24 + 50].try_into().unwrap()),
        10
    );
}

#[test]
fn cyclic_response_file_is_an_error() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("cycle.rsp");
    std::fs::write(&path, format!("@\"{}\"", path.display())).unwrap();
    let mut args = CoffArgs::default();
    let error = crate::args::coff::parse(&mut args, [format!("@{}", path.display())].into_iter())
        .unwrap_err();
    assert!(error.to_string().contains("cycle"));
}

#[test]
fn negative_rva_addend_is_sign_extended() {
    let mut o = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let code = o.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    o.append_section_data(code, &[0xc3], 16);
    o.add_symbol(Symbol {
        name: b"entry".to_vec(),
        value: 0,
        size: 1,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(code),
        flags: SymbolFlags::None,
    });
    let data = o.add_section(Vec::new(), b".rdata".to_vec(), SectionKind::ReadOnlyData);
    o.append_section_data(data, &[0u8; 32], 8);
    let target = o.add_symbol(Symbol {
        name: b"table".to_vec(),
        value: 24,
        size: 8,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(data),
        flags: SymbolFlags::None,
    });
    o.add_relocation(
        data,
        Relocation {
            offset: 0,
            symbol: target,
            addend: -24,
            flags: RelocationFlags::Coff {
                typ: object::pe::IMAGE_REL_AMD64_ADDR32NB,
            },
        },
    )
    .unwrap();
    let bytes = link_objects(&[o.write().unwrap()], |_| {}).unwrap();
    let pe = object::read::pe::PeFile64::parse(&*bytes).unwrap();
    let section = pe.section_by_name(".rdata").unwrap();
    let actual = u32::from_le_bytes(section.data().unwrap()[..4].try_into().unwrap());
    assert_eq!(actual as u64, section.address() - 0x140000000);
}

fn caller(target: &str) -> Vec<u8> {
    let mut o = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let section = o.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    o.append_section_data(section, &[0xe8, 0, 0, 0, 0, 0xc3], 16);
    o.add_symbol(Symbol {
        name: b"entry".to_vec(),
        value: 0,
        size: 6,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(section),
        flags: SymbolFlags::None,
    });
    let target = o.add_symbol(Symbol {
        name: target.as_bytes().to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });
    o.add_relocation(
        section,
        Relocation {
            offset: 1,
            symbol: target,
            addend: -4,
            flags: RelocationFlags::Coff {
                typ: object::pe::IMAGE_REL_AMD64_REL32,
            },
        },
    )
    .unwrap();
    o.write().unwrap()
}

#[test]
fn weak_alias_extracts_archive_member() {
    let weak = symbol_object("builtin", &[0xc3], None, true);
    let mut builder = ar::Builder::new(Vec::new());
    builder
        .append(
            &ar::Header::new(b"weak.obj".to_vec(), weak.len() as u64),
            &*weak,
        )
        .unwrap();
    let bytes = link_objects(&[caller("builtin"), builder.into_inner().unwrap()], |_| {}).unwrap();
    let pe = object::read::pe::PeFile64::parse(&*bytes).unwrap();
    let code = pe.section_by_name(".text").unwrap().data().unwrap();
    let displacement = i32::from_le_bytes(code[1..5].try_into().unwrap());
    assert_eq!(code[(5 + displacement) as usize], 0xc3);
}

#[test]
fn strong_definition_overrides_weak_alias() {
    let bytes = link_objects(
        &[
            caller("builtin"),
            symbol_object("builtin", &[0xcc], None, true),
            object("builtin", &[0xc3], None),
        ],
        |_| {},
    )
    .unwrap();
    let pe = object::read::pe::PeFile64::parse(&*bytes).unwrap();
    let code = pe.section_by_name(".text").unwrap().data().unwrap();
    let displacement = i32::from_le_bytes(code[1..5].try_into().unwrap());
    assert_eq!(code[(5 + displacement) as usize], 0xc3);
}
