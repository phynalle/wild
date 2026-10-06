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
use object::read::coff::Symbol as _;
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

#[test]
fn defined_weak_fallback_does_not_extract_a_library_definition() {
    let weak = symbol_object("builtin", &[0xc3], None, true);
    let parsed = match input::parse(&weak, "weak.obj".into()).unwrap() {
        input::Parsed::Object(o) => o,
        _ => unreachable!(),
    };
    let fallback = parsed
        .symbols
        .iter()
        .find_map(input::Symbol::weak)
        .unwrap()
        .0;
    let name = std::str::from_utf8(&weak[parsed.symbols[fallback].name.range()]).unwrap();
    assert!(parsed.symbols[fallback].section > 0);
    let archive = indexed_archive(&[object(name, &[0xcc], None)], &[(name, 0)]);
    let temp = tempfile::tempdir().unwrap();
    let mut args = CoffArgs::default();
    args.entry = Some("entry".into());
    for (i, bytes) in [caller("builtin"), weak, archive].iter().enumerate() {
        let path = temp.path().join(format!("{i}.obj"));
        std::fs::write(&path, bytes).unwrap();
        args.common.inputs.push(Input {
            spec: InputSpec::File(path.into()),
            modifiers: Modifiers::default(),
            search_first: None,
        });
    }
    let mut r = resolve::Resolver::new(&crate::OsFileSystem, &args);
    r.load().unwrap();
    r.resolve().unwrap();
    assert!(!r.objects[2].parsed);
}

#[test]
fn coff_metadata_uses_compact_indices() {
    assert!(std::mem::size_of::<input::Symbol>() <= 40);
    assert_eq!(std::mem::size_of::<Option<input::ResolvedTarget>>(), 8);
    assert!(std::mem::size_of::<input::Section>() <= 96);
    assert_eq!(std::mem::size_of::<input::ByteRange>(), 8);
}

fn associative_object(name: &str, value: u8) -> Vec<u8> {
    let mut o = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let root = o.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    o.append_section_data(root, &[0xc3], 16);
    o.section_symbol(root);
    let symbol = o.add_symbol(Symbol {
        name: name.as_bytes().to_vec(),
        value: 0,
        size: 1,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(root),
        flags: SymbolFlags::None,
    });
    let mut sections = vec![root];
    for suffix in [b".rdata$a".as_slice(), b".rdata$b".as_slice()] {
        let child = o.add_section(Vec::new(), suffix.to_vec(), SectionKind::ReadOnlyData);
        o.append_section_data(child, &[value], 1);
        o.section_symbol(child);
        sections.push(child);
    }
    o.add_comdat(Comdat {
        kind: ComdatKind::Any,
        symbol,
        sections,
    });
    o.write().unwrap()
}

#[test]
fn associative_children_follow_live_selected_parent() {
    let bytes = link_objects(
        &[
            associative_object("entry", 0x11),
            associative_object("entry", 0x22),
            associative_object("dead", 0x33),
        ],
        |_| {},
    )
    .unwrap();
    let pe = object::read::pe::PeFile64::parse(&*bytes).unwrap();
    assert_eq!(
        &pe.section_by_name(".rdata").unwrap().data().unwrap()[..2],
        &[0x11, 0x11]
    );
}

#[test]
fn associative_children_index_preserves_section_order() {
    let input::Parsed::Object(o) =
        input::parse(&associative_object("entry", 1), "test.obj".into()).unwrap()
    else {
        panic!("object expected")
    };
    assert_eq!(o.child_offsets, [0, 2, 2, 2]);
    assert_eq!(o.children, [1, 2]);
}

#[test]
fn comdat_representative_is_first_external_at_zero() {
    let mut o = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let section = o.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    o.append_section_data(section, &[0x90, 0xc3], 1);
    o.section_symbol(section);
    let mut first = None;
    for (name, value, scope) in [
        ("static", 0, SymbolScope::Compilation),
        ("nonzero", 1, SymbolScope::Linkage),
        ("entry", 0, SymbolScope::Linkage),
        ("second", 0, SymbolScope::Linkage),
    ] {
        let s = o.add_symbol(Symbol {
            name: name.as_bytes().to_vec(),
            value,
            size: 1,
            kind: SymbolKind::Text,
            scope,
            weak: false,
            section: SymbolSection::Section(section),
            flags: SymbolFlags::None,
        });
        if name == "entry" {
            first = Some(s);
        }
    }
    o.add_comdat(Comdat {
        kind: ComdatKind::Any,
        symbol: first.unwrap(),
        sections: vec![section],
    });
    let bytes = o.write().unwrap();
    let input::Parsed::Object(parsed) = input::parse(&bytes, "test.obj".into()).unwrap() else {
        panic!("object expected")
    };
    let representative = parsed.sections[0].key_symbol.unwrap();
    assert_eq!(
        &bytes[parsed.symbols[representative as usize].name.range()],
        b"entry"
    );
}

fn archive(members: &[Vec<u8>]) -> Vec<u8> {
    let mut builder = ar::Builder::new(Vec::new());
    for (i, member) in members.iter().enumerate() {
        builder
            .append(
                &ar::Header::new(format!("{i}.obj").into_bytes(), member.len() as u64),
                &**member,
            )
            .unwrap();
    }
    builder.into_inner().unwrap()
}

fn renamed_caller(name: &str, target: &str) -> Vec<u8> {
    let mut bytes = caller(target);
    // Both names occupy the same inline COFF symbol field.
    assert!(name.len() <= 8);
    let file =
        object::read::coff::CoffFile::<_, object::pe::ImageFileHeader>::parse(&*bytes).unwrap();
    let table = file.coff_symbol_table();
    let (_, entry) = table
        .iter()
        .find(|(_, s)| s.name(table.strings()).unwrap() == b"entry")
        .unwrap();
    let offset = entry as *const _ as usize - bytes.as_ptr() as usize;
    bytes[offset..offset + 8].fill(0);
    bytes[offset..offset + name.len()].copy_from_slice(name.as_bytes());
    bytes
}

#[test]
fn worklist_resolves_multiple_archive_waves_and_cycles() {
    let bytes = link_objects(
        &[
            caller("first"),
            archive(&[renamed_caller("second", "first")]),
            archive(&[renamed_caller("first", "second")]),
        ],
        |_| {},
    )
    .unwrap();
    let pe = object::read::pe::PeFile64::parse(&*bytes).unwrap();
    assert!(pe.section_by_name(".text").unwrap().data().unwrap().len() >= 38);
}

#[test]
fn worklist_retries_when_activated_member_adds_defaultlib() {
    let temp = tempfile::tempdir().unwrap();
    let lib = temp.path().join("later.lib");
    std::fs::write(&lib, archive(&[object("later", &[0xc3], None)])).unwrap();
    let mut o = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let directives = o.add_section(Vec::new(), b".drectve".to_vec(), SectionKind::Linker);
    o.append_section_data(
        directives,
        format!("/DEFAULTLIB:\"{}\" /INCLUDE:later", lib.display()).as_bytes(),
        1,
    );
    let bytes = link_objects(
        &[
            caller("first"),
            archive(&[object("first", &[0xc3], None), o.write().unwrap()]),
        ],
        |a| {
            a.directives.push("/WHOLEARCHIVE".into());
        },
    )
    .unwrap();
    assert!(object::read::pe::PeFile64::parse(&*bytes).is_ok());
}

#[test]
fn time_option_enables_common_timing() {
    let mut args = CoffArgs::default();
    crate::args::coff::parse(&mut args, ["/TIME"].into_iter()).unwrap();
    assert!(args.common.time_phase_options.as_ref().unwrap().is_empty());
}

#[test]
fn output_write_modes_are_byte_identical() {
    let o = object("entry", &[0xc3], None);
    let buffered = link_objects(&[o.clone()], |a| {
        a.common.file_write_mode = Some(crate::fs::FileWriteMode::BufferThenWrite)
    })
    .unwrap();
    let mapped = link_objects(&[o], |a| {
        a.common.file_write_mode = Some(crate::fs::FileWriteMode::Mmap)
    })
    .unwrap();
    assert_eq!(buffered, mapped);
}

#[test]
fn output_options_preserve_explicit_modes() {
    use crate::fs::FileReplacementMode;
    use crate::fs::FileWriteMode;
    let mut args = CoffArgs::default();
    for (option, expected) in [
        ("/UPDATE-IN-PLACE", FileReplacementMode::UpdateInPlace),
        ("/NO-UPDATE-IN-PLACE", FileReplacementMode::UnlinkAndReplace),
        (
            "/UPDATE-IN-PLACE-WITH-FALLBACK",
            FileReplacementMode::UpdateInPlaceWithFallback,
        ),
    ] {
        crate::args::coff::parse(&mut args, [option].into_iter()).unwrap();
        assert_eq!(args.common.file_replacement_mode, Some(expected));
    }
    for (option, expected) in [
        ("/MMAP-OUTPUT-FILE", FileWriteMode::Mmap),
        ("/NO-MMAP-OUTPUT-FILE", FileWriteMode::BufferThenWrite),
    ] {
        crate::args::coff::parse(&mut args, [option].into_iter()).unwrap();
        assert!(matches!(
            (args.common.file_write_mode, expected),
            (Some(FileWriteMode::Mmap), FileWriteMode::Mmap)
                | (
                    Some(FileWriteMode::BufferThenWrite),
                    FileWriteMode::BufferThenWrite
                )
        ));
    }
}

#[test]
fn complete_output_honors_replacement_and_shrinks() {
    use crate::fs::FileReplacementMode;
    use crate::fs::FileSystem;
    use crate::fs::FileWriteMode;
    use crate::fs::OutputOptions;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("output.exe");
    let alias = temp.path().join("alias.exe");
    for mode in [
        FileReplacementMode::UnlinkAndReplace,
        FileReplacementMode::UpdateInPlace,
        FileReplacementMode::UpdateInPlaceWithFallback,
    ] {
        std::fs::write(&path, b"old output").unwrap();
        std::fs::hard_link(&path, &alias).unwrap();
        crate::OsFileSystem
            .write_output(
                Arc::from(path.as_path()),
                OutputOptions {
                    size: 3,
                    file_replacement_mode: mode,
                    write_mode: Some(FileWriteMode::BufferThenWrite),
                    fallocate: Some(false),
                    madvise_huge_pages: Some(false),
                },
                b"new",
            )
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(
            std::fs::read(&alias).unwrap(),
            if mode == FileReplacementMode::UpdateInPlace {
                b"new".as_slice()
            } else {
                b"old output".as_slice()
            }
        );
        std::fs::remove_file(&alias).unwrap();
    }
}

fn indexed_archive(members: &[Vec<u8>], symbols: &[(&str, usize)]) -> Vec<u8> {
    let size = 4
        + symbols.len() * 4
        + symbols
            .iter()
            .map(|(name, _)| name.len() + 1)
            .sum::<usize>();
    let mut offset = 8 + 60 + size.next_multiple_of(2);
    let offsets: Vec<_> = members
        .iter()
        .map(|member| {
            let current = offset;
            offset += 60 + member.len().next_multiple_of(2);
            current as u32
        })
        .collect();
    let mut index = (symbols.len() as u32).to_be_bytes().to_vec();
    for (_, member) in symbols {
        index.extend_from_slice(&offsets[*member].to_be_bytes());
    }
    for (name, _) in symbols {
        index.extend_from_slice(name.as_bytes());
        index.push(0);
    }
    let mut builder = ar::Builder::new(Vec::new());
    builder
        .append(&ar::Header::new(b"/".to_vec(), index.len() as u64), &*index)
        .unwrap();
    for (i, member) in members.iter().enumerate() {
        builder
            .append(
                &ar::Header::new(format!("{i}.obj").into_bytes(), member.len() as u64),
                &**member,
            )
            .unwrap();
    }
    builder.into_inner().unwrap()
}

#[test]
fn indexed_archive_parses_only_extracted_member() {
    let temp = tempfile::tempdir().unwrap();
    let mut args = CoffArgs::default();
    args.entry = Some("entry".into());
    let members = [
        object("needed", &[0xc3], None),
        object("unused", &[0xcc], None),
    ];
    for (i, bytes) in [
        caller("needed"),
        indexed_archive(&members, &[("unused", 1), ("needed", 0)]),
    ]
    .iter()
    .enumerate()
    {
        let path = temp.path().join(format!("{i}.obj"));
        std::fs::write(&path, bytes).unwrap();
        args.common.inputs.push(Input {
            spec: InputSpec::File(path.into()),
            modifiers: Modifiers::default(),
            search_first: None,
        });
    }
    let mut r = resolve::Resolver::new(&crate::OsFileSystem, &args);
    r.load().unwrap();
    assert_eq!(r.objects.iter().filter(|o| o.parsed).count(), 1);
    r.resolve().unwrap();
    assert_eq!(r.objects.iter().filter(|o| o.parsed).count(), 2);
    assert!(!r.objects[2].parsed);
    assert_eq!(r.section_data(1, 0), &[0xc3]);
}

#[test]
fn incomplete_index_and_unindexed_weak_alias_have_fallbacks() {
    let members = [
        object("needed", &[0xc3], None),
        object("unused", &[0xcc], None),
    ];
    assert!(
        link_objects(
            &[
                caller("needed"),
                indexed_archive(&members, &[("unused", 1)])
            ],
            |_| {}
        )
        .is_ok()
    );
    let weak = symbol_object("builtin", &[0xc3], None, true);
    assert!(
        link_objects(
            &[
                caller("builtin"),
                indexed_archive(&[weak, members[1].clone()], &[("unused", 1)])
            ],
            |_| {}
        )
        .is_ok()
    );
}

#[test]
fn archive_index_order_does_not_change_member_precedence() {
    let members = [
        object("needed", &[0xc3], None),
        object("needed", &[0xcc], None),
    ];
    let bytes = link_objects(
        &[
            caller("needed"),
            indexed_archive(&members, &[("needed", 1), ("needed", 0)]),
        ],
        |_| {},
    )
    .unwrap();
    let pe = object::read::pe::PeFile64::parse(&*bytes).unwrap();
    let code = pe.section_by_name(".text").unwrap().data().unwrap();
    let displacement = i32::from_le_bytes(code[1..5].try_into().unwrap());
    assert_eq!(code[(5 + displacement) as usize], 0xc3);
}

#[test]
fn thread_options_set_shared_pool_configuration() {
    let mut args = CoffArgs::default();
    crate::args::coff::parse(&mut args, ["/THREADS:2"].into_iter()).unwrap();
    assert_eq!(args.common.num_threads.unwrap().get(), 2);
    crate::args::coff::parse(&mut args, ["/NO-THREADS"].into_iter()).unwrap();
    assert_eq!(args.common.num_threads.unwrap().get(), 1);
    assert!(crate::args::coff::parse(&mut args, ["/THREADS:0"].into_iter()).is_err());
}

#[test]
fn parallel_parsing_and_relocation_are_byte_deterministic() {
    let temp = tempfile::tempdir().unwrap();
    let mut args = CoffArgs::default();
    args.entry = Some("entry".into());
    args.common.output = Arc::from(temp.path().join("output.exe"));
    args.directives
        .extend(["/INCLUDE:one".into(), "/INCLUDE:two".into()]);
    let members = [
        pointer_object("one", "entry", 65536),
        pointer_object("two", "entry", 65536),
        object("needed", &[0xc3], None),
    ];
    for (i, bytes) in [
        caller("needed"),
        indexed_archive(&members, &[("one", 0), ("two", 1), ("needed", 2)]),
    ]
    .iter()
    .enumerate()
    {
        let path = temp.path().join(format!("{i}.obj"));
        std::fs::write(&path, bytes).unwrap();
        args.common.inputs.push(Input {
            spec: InputSpec::File(path.into()),
            modifiers: Modifiers::default(),
            search_first: None,
        });
    }
    let mut expected = None;
    for threads in [1, 2, 4] {
        args.common.num_threads = std::num::NonZeroUsize::new(threads);
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
            .install(|| link(&crate::OsFileSystem, &args))
            .unwrap();
        let image = std::fs::read(&args.common.output).unwrap();
        let pe = object::read::pe::PeFile64::parse(&*image).unwrap();
        let pointers = pe.section_by_name(".rdata").unwrap().data().unwrap();
        assert_eq!(
            u64::from_le_bytes(pointers[..8].try_into().unwrap()),
            pe.entry()
        );
        if let Some(expected) = &expected {
            assert_eq!(&image, expected);
        } else {
            expected = Some(image);
        }
    }
    let mut invalid = caller("needed");
    let file =
        object::read::coff::CoffFile::<_, object::pe::ImageFileHeader>::parse(&*invalid).unwrap();
    let section = file.sections().next().unwrap();
    let relocs = section.coff_relocations().unwrap();
    let offset = std::ptr::addr_of!(relocs[0].typ) as usize - invalid.as_ptr() as usize;
    invalid[offset..offset + 2].copy_from_slice(&0xffffu16.to_le_bytes());
    std::fs::write(temp.path().join("0.obj"), invalid).unwrap();
    let mut previous_error = None;
    for threads in [1, 2, 4] {
        args.common.num_threads = std::num::NonZeroUsize::new(threads);
        let error = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
            .install(|| link(&crate::OsFileSystem, &args))
            .unwrap_err()
            .to_string();
        assert!(error.contains("Unsupported x64 COFF relocation"));
        if let Some(previous) = &previous_error {
            assert_eq!(&error, previous);
        } else {
            previous_error = Some(error);
        }
        assert_eq!(
            &std::fs::read(&args.common.output).unwrap(),
            expected.as_ref().unwrap()
        );
    }
}

fn pointer_object(name: &str, target: &str, count: usize) -> Vec<u8> {
    let mut o = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let section = o.add_section(Vec::new(), b".rdata".to_vec(), SectionKind::ReadOnlyData);
    o.append_section_data(section, &vec![0; count * 8], 8);
    o.add_symbol(Symbol {
        name: name.as_bytes().to_vec(),
        value: 0,
        size: (count * 8) as u64,
        kind: SymbolKind::Data,
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
    for i in 0..count {
        o.add_relocation(
            section,
            Relocation {
                offset: (i * 8) as u64,
                symbol: target,
                addend: 0,
                flags: RelocationFlags::Coff {
                    typ: object::pe::IMAGE_REL_AMD64_ADDR64,
                },
            },
        )
        .unwrap();
    }
    o.write().unwrap()
}

#[test]
fn nested_associative_comdats_follow_the_parent_chain() {
    let mut bytes = associative_object("entry", 0x44);
    let file =
        object::read::coff::CoffFile::<_, object::pe::ImageFileHeader>::parse(&*bytes).unwrap();
    let table = file.coff_symbol_table();
    let (index, _) = table
        .iter()
        .find(|(_, s)| s.section_number().0 == 3 && s.has_aux_section())
        .unwrap();
    let aux = table.aux_section(index).unwrap();
    let offset = std::ptr::addr_of!(aux.number) as usize - bytes.as_ptr() as usize;
    bytes[offset..offset + 2].copy_from_slice(&2u16.to_le_bytes());
    let image = link_objects(&[bytes], |_| {}).unwrap();
    let pe = object::read::pe::PeFile64::parse(&*image).unwrap();
    assert_eq!(
        &pe.section_by_name(".rdata").unwrap().data().unwrap()[..2],
        &[0x44, 0x44]
    );
}
