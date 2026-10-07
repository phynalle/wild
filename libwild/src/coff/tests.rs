use super::*;
use crate::args::Input;
use crate::args::InputSpec;
use crate::args::Modifiers;
use crate::args::coff::CoffArgs;
use crate::error::Result;
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
    Ok(link_development_outputs(objects, extra)?.0)
}

fn link_development_outputs(
    objects: &[Vec<u8>],
    extra: impl FnOnce(&mut CoffArgs),
) -> Result<(Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>)> {
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
    let output = args.common.output.clone();
    let args = crate::args::Args::Coff(args);
    let linker = crate::Linker::new();
    drop(linker.run(&args)?);
    Ok((
        std::fs::read(&output).unwrap(),
        std::fs::read(output.with_extension("pdb")).ok(),
        std::fs::read(output.with_extension("lib")).ok(),
    ))
}

#[test]
fn dll_export_roots_extract_archive_members_and_write_import_library() {
    let (image, _, library) = link_development_outputs(
        &[
            object("entry", &[0xc3], None),
            archive(&[object("exported", &[0x90, 0xc3], None)]),
        ],
        |args| {
            args.is_dll = true;
            args.directives.push("/EXPORT:public=exported".into());
        },
    )
    .unwrap();
    let pe = object::read::pe::PeFile64::parse(&*image).unwrap();
    let exports: Vec<_> = object::Object::exports(&pe)
        .unwrap()
        .map(|export| export.unwrap())
        .collect();
    assert_eq!(exports.len(), 1);
    assert_eq!(
        exports[0].name(),
        object::NameOrOrdinal::Name(&b"public"[..])
    );
    assert_ne!(
        u16::from_le_bytes(image[0x96..0x98].try_into().unwrap()) & 0x2000,
        0
    );
    assert!(library.unwrap().starts_with(b"!<arch>\n"));
}

#[test]
fn noentry_dll_has_zero_entry_and_dll_image_base() {
    let image = link_objects(&[object("entry", &[0xc3], None)], |args| {
        args.is_dll = true;
        args.no_entry = true;
        args.entry = None;
        args.image_base = 0x180000000;
        args.directives.push("/EXPORT:entry".into());
    })
    .unwrap();
    assert_eq!(u32::from_le_bytes(image[0xa8..0xac].try_into().unwrap()), 0);
    assert_eq!(
        u64::from_le_bytes(image[0xb0..0xb8].try_into().unwrap()),
        0x180000000
    );
}

#[test]
fn debug_output_uses_shared_auxiliary_writer() {
    let (image, pdb, _) = link_development_outputs(&[object("entry", &[0xc3], None)], |args| {
        args.debug = true;
        args.pdb_alt_path = Some("%_PDB%".into());
    })
    .unwrap();
    assert!(
        pdb.unwrap()
            .starts_with(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0")
    );
    assert!(image.windows(4).any(|bytes| bytes == b"RSDS"));
    assert!(image.windows(10).any(|bytes| bytes == b"image.pdb\0"));
}

#[test]
fn malformed_debug_is_checked_only_when_debugging_is_enabled() {
    let mut o = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let text = o.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    o.append_section_data(text, &[0xc3], 16);
    o.add_symbol(Symbol {
        name: b"entry".to_vec(),
        value: 0,
        size: 1,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    let debug = o.add_section(Vec::new(), b".debug$T".to_vec(), SectionKind::Debug);
    o.append_section_data(debug, &[4, 0, 0, 0, 10, 0, 1, 0x10], 4);
    let bytes = o.write().unwrap();
    assert!(link_objects(&[bytes.clone()], |_| {}).is_ok());
    assert!(
        link_objects(
            &[object("entry", &[0xc3], None), archive(&[bytes.clone()])],
            |args| args.debug = true
        )
        .is_ok()
    );
    let error = link_objects(&[bytes], |args| args.debug = true).unwrap_err();
    assert!(error.to_string().contains("Truncated CodeView record"));
}

#[test]
fn debug_address_below_image_base_is_a_link_error() {
    let mut o = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let debug = o.add_section(Vec::new(), b".debug$S".to_vec(), SectionKind::Debug);
    o.append_section_data(debug, &4u32.to_le_bytes(), 4);
    let symbol = o.add_symbol(Symbol {
        name: b"absolute".to_vec(),
        value: 1,
        size: 0,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Absolute,
        flags: SymbolFlags::None,
    });
    o.add_relocation(
        debug,
        Relocation {
            offset: 0,
            symbol,
            addend: 0,
            flags: RelocationFlags::Coff {
                typ: object::pe::IMAGE_REL_AMD64_ADDR32NB,
            },
        },
    )
    .unwrap();
    let error = link_objects(
        &[object("entry", &[0xc3], None), o.write().unwrap()],
        |args| args.debug = true,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("Debug ADDR32NB overflow"), "{error}");
}

#[test]
fn conflicting_outputs_are_rejected_before_truncating_image() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("sentinel.exe");
    std::fs::write(&path, b"sentinel").unwrap();
    let mut args = CoffArgs::default();
    args.common.output = Arc::from(path.clone());
    args.debug = true;
    args.pdb = Some(Arc::from(temp.path().join("./sentinel.exe")));
    let linker = crate::Linker::new();
    let args = crate::args::Args::Coff(args);
    let error = linker.run(&args).err().unwrap();
    assert!(error.to_string().contains("Conflicting output path"));
    assert_eq!(std::fs::read(path).unwrap(), b"sentinel");
}

#[test]
fn late_export_output_conflict_preserves_existing_outputs() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("input.obj");
    std::fs::write(&input, object("entry", &[0xc3], None)).unwrap();
    let directives = temp.path().join("directives.obj");
    let mut o = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let section = o.add_section(Vec::new(), b".drectve".to_vec(), SectionKind::Linker);
    o.append_section_data(section, b"/EXPORT:entry", 1);
    std::fs::write(&directives, o.write().unwrap()).unwrap();
    let output = temp.path().join("image.exe");
    let sidecar = output.with_extension("lib");
    std::fs::write(&output, b"image sentinel").unwrap();
    std::fs::write(&sidecar, b"sidecar sentinel").unwrap();
    let mut args = CoffArgs::default();
    args.entry = Some("entry".into());
    args.debug = true;
    args.pdb = Some(Arc::from(sidecar.clone()));
    args.common.output = Arc::from(output.clone());
    args.common.inputs.push(Input {
        spec: InputSpec::File(input.into()),
        modifiers: Modifiers::default(),
        search_first: None,
    });
    args.common.inputs.push(Input {
        spec: InputSpec::File(directives.into()),
        modifiers: Modifiers::default(),
        search_first: None,
    });
    let linker = crate::Linker::new();
    let error = linker
        .run(&crate::args::Args::Coff(args))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("Conflicting output path"), "{error}");
    assert_eq!(std::fs::read(output).unwrap(), b"image sentinel");
    assert_eq!(std::fs::read(sidecar).unwrap(), b"sidecar sentinel");
}

#[test]
fn auxiliary_output_failure_is_a_link_failure() {
    for extension in ["pdb", "lib"] {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input.obj");
        std::fs::write(&input, object("entry", &[0xc3], None)).unwrap();
        let output = temp.path().join("image.dll");
        std::fs::create_dir(output.with_extension(extension)).unwrap();
        let mut args = CoffArgs::default();
        args.entry = Some("entry".into());
        args.is_dll = true;
        args.debug = true;
        args.common.output = Arc::from(output);
        args.directives.push("/EXPORT:entry".into());
        args.common.inputs.push(Input {
            spec: InputSpec::File(input.into()),
            modifiers: Modifiers::default(),
            search_first: None,
        });
        let linker = crate::Linker::new();
        assert!(linker.run(&crate::args::Args::Coff(args)).is_err());
    }
}

#[test]
fn development_outputs_are_thread_and_write_mode_independent() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("input.obj");
    std::fs::write(&input, object("entry", &[0xc3], None)).unwrap();
    let output = temp.path().join("image.dll");
    let mut expected = None;
    for threads in [1, 2, 4] {
        for mode in [
            crate::fs::FileWriteMode::BufferThenWrite,
            crate::fs::FileWriteMode::Mmap,
        ] {
            let mut args = CoffArgs::default();
            args.entry = Some("entry".into());
            args.is_dll = true;
            args.debug = true;
            args.common.output = Arc::from(output.clone());
            args.common.available_threads = std::num::NonZeroUsize::new(threads).unwrap();
            args.common.file_write_mode = Some(mode);
            args.directives.push("/EXPORT:entry".into());
            args.common.inputs.push(Input {
                spec: InputSpec::File(input.clone().into()),
                modifiers: Modifiers::default(),
                search_first: None,
            });
            let linker = crate::Linker::new();
            let args = crate::args::Args::Coff(args);
            drop(linker.run(&args).unwrap());
            let actual = (
                std::fs::read(&output).unwrap(),
                std::fs::read(output.with_extension("pdb")).unwrap(),
                std::fs::read(output.with_extension("lib")).unwrap(),
            );
            if let Some(expected) = &expected {
                assert_eq!(&actual, expected);
            } else {
                expected = Some(actual);
            }
        }
    }
}

#[test]
fn explicit_strong_definition_prevents_earlier_archive_extraction() {
    let image = link_objects(
        &[
            archive(&[object("entry", &[0xcc], None)]),
            object("entry", &[0xc3], None),
        ],
        |_| {},
    )
    .unwrap();
    let pe = object::read::pe::PeFile64::parse(&*image).unwrap();
    assert_eq!(
        pe.section_by_name(".text").unwrap().data().unwrap()[0],
        0xc3
    );
}

#[test]
fn unselected_archive_definition_does_not_infer_entry() {
    let image = link_objects(
        &[
            object("mainCRTStartup", &[0xc3], None),
            archive(&[object("wmain", &[0xcc], None)]),
        ],
        |args| {
            args.entry = None;
        },
    )
    .unwrap();
    let pe = object::read::pe::PeFile64::parse(&*image).unwrap();
    assert_eq!(
        pe.section_by_name(".text").unwrap().data().unwrap()[0],
        0xc3
    );
}

#[test]
fn activated_archive_definition_can_infer_entry() {
    let image = link_objects(
        &[
            object("mainCRTStartup", &[0xc3], None),
            object("wmainCRTStartup", &[0x90, 0xc3], None),
            archive(&[object("wmain", &[0xcc], None)]),
        ],
        |args| {
            args.entry = None;
            args.directives.push("/INCLUDE:wmain".into());
        },
    )
    .unwrap();
    let pe = object::read::pe::PeFile64::parse(&*image).unwrap();
    let text = pe.section_by_name(".text").unwrap();
    assert_eq!(
        text.data().unwrap()[(pe.entry() - text.address()) as usize],
        0x90
    );
}

#[test]
fn cyclic_weak_external_is_a_link_error() {
    let mut bytes = symbol_object("entry", &[0xc3], None, true);
    let parsed = match input::parse(&bytes, "weak.obj".into()).unwrap() {
        input::Parsed::Object(o) => o,
        _ => unreachable!(),
    };
    let index = parsed
        .symbols
        .iter()
        .position(|s| s.weak().is_some())
        .unwrap();
    let table = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let auxiliary = table + (index + 1) * 18;
    bytes[auxiliary..auxiliary + 4].copy_from_slice(&(index as u32).to_le_bytes());
    let error = link_objects(&[bytes], |_| {}).unwrap_err().to_string();
    assert!(error.contains("Weak external cycle"), "{error}");
}

#[test]
fn absolute_entry_below_image_base_is_a_link_error() {
    let mut o = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    o.add_symbol(Symbol {
        name: b"entry".to_vec(),
        value: 1,
        size: 0,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Absolute,
        flags: SymbolFlags::None,
    });
    let error = link_objects(&[o.write().unwrap()], |_| {})
        .unwrap_err()
        .to_string();
    assert!(error.contains("below image base"), "{error}");
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
fn imported_thunk_points_at_the_start_of_its_iat_slot() {
    let payload = b"imported\0example.dll\0";
    let mut import = vec![0; 20];
    import[..4].copy_from_slice(&[0, 0, 0xff, 0xff]);
    import[6..8].copy_from_slice(&0x8664u16.to_le_bytes());
    import[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    import[18..20].copy_from_slice(&4u16.to_le_bytes());
    import.extend_from_slice(payload);
    let image = link_objects(&[caller("imported"), archive(&[import])], |_| {}).unwrap();
    let pe = object::read::pe::PeFile64::parse(&*image).unwrap();
    let text = pe.section_by_name(".text").unwrap();
    let code = text.data().unwrap();
    let call = i32::from_le_bytes(code[1..5].try_into().unwrap());
    let thunk = (5 + call) as usize;
    assert_eq!(&code[thunk..thunk + 2], &[0xff, 0x25]);
    let displacement = i32::from_le_bytes(code[thunk + 2..thunk + 6].try_into().unwrap());
    let target = (text.address() as i64 + thunk as i64 + 6 + i64::from(displacement)) as u64;
    let iat = pe
        .data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_IAT)
        .unwrap();
    assert_eq!(
        target,
        0x140000000 + u64::from(iat.virtual_address.get(object::LittleEndian))
    );
}

#[test]
fn short_import_names_borrow_validated_input() {
    let payload = b"imported\0example.dll\0";
    let mut bytes = vec![0; 20];
    bytes[..4].copy_from_slice(&[0, 0, 0xff, 0xff]);
    bytes[6..8].copy_from_slice(&0x8664u16.to_le_bytes());
    bytes[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes[18..20].copy_from_slice(&4u16.to_le_bytes());
    bytes.extend_from_slice(payload);
    let input::Parsed::Import(import) = input::parse(&bytes, "import.obj".into()).unwrap() else {
        panic!("Expected an import");
    };
    for name in [import.symbol, import.dll, import.name.unwrap()] {
        let start = name.as_ptr() as usize - bytes.as_ptr() as usize;
        assert!(start <= bytes.len() && name.len() <= bytes.len() - start);
    }
    for end in 0..bytes.len() {
        assert!(input::parse(&bytes[..end], "truncated.obj".into()).is_err());
    }
    let image = link_objects(&[caller("imported"), archive(&[bytes])], |_| {}).unwrap();
    assert!(object::read::pe::PeFile64::parse(&*image).is_ok());
}

fn short_import(symbol: &str, dll: &str) -> Vec<u8> {
    let payload = format!("{symbol}\0{dll}\0");
    let mut bytes = vec![0; 20];
    bytes[..4].copy_from_slice(&[0, 0, 0xff, 0xff]);
    bytes[6..8].copy_from_slice(&0x8664u16.to_le_bytes());
    bytes[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes[18..20].copy_from_slice(&4u16.to_le_bytes());
    bytes.extend_from_slice(payload.as_bytes());
    bytes
}

#[test]
fn optional_import_coalescing_preserves_order_overrides_and_wholearchive() {
    let first = short_import("imported", "first.dll");
    let other = short_import("imported", "other.dll");
    let repeated = [
        caller("imported"),
        archive(&vec![first.clone(); 64]),
        archive(&[other.clone(), first.clone()]),
        archive(&[first.clone()]),
    ];
    let expected = link_objects(&[caller("imported"), archive(&[first.clone()])], |_| {}).unwrap();
    for threads in [1, 2, 16] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        let image = pool.install(|| link_objects(&repeated, |_| {})).unwrap();
        assert_eq!(expected, image);
    }
    let reordered = link_objects(
        &[
            caller("imported"),
            archive(&[other.clone()]),
            archive(&[first.clone()]),
        ],
        |_| {},
    )
    .unwrap();
    let expected_other = link_objects(&[caller("imported"), archive(&[other])], |_| {}).unwrap();
    assert_eq!(expected_other, reordered);
    assert_ne!(expected, reordered);

    let strong = object("imported", &[0xc3], None);
    let mut overridden = repeated.to_vec();
    overridden.push(strong.clone());
    let overridden = link_objects(&overridden, |_| {}).unwrap();
    let expected_strong = link_objects(&[caller("imported"), strong], |_| {}).unwrap();
    assert_eq!(expected_strong, overridden);

    // An unreferenced mandatory copy must activate even if an identical optional copy came first.
    let mandatory = link_objects(
        &[
            object("entry", &[0xc3], None),
            archive(&[first.clone()]),
            archive(&[first]),
        ],
        |args| {
            args.common
                .inputs
                .last_mut()
                .unwrap()
                .modifiers
                .whole_archive = true
        },
    )
    .unwrap();
    let pe = object::read::pe::PeFile64::parse(&*mandatory).unwrap();
    assert_ne!(
        pe.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_IMPORT)
            .unwrap()
            .virtual_address
            .get(object::LittleEndian),
        0
    );
}

#[test]
fn sharded_comdat_selection_preserves_output_and_first_error() {
    let mut padding = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    for _ in 0..4096 {
        padding.add_section(Vec::new(), b".rdata".to_vec(), SectionKind::ReadOnlyData);
    }
    let padding = padding.write().unwrap();
    let first = "first";
    let second = (0..100)
        .map(|i| format!("other{i}"))
        .find(|name| {
            crate::hash::hash_bytes(name.as_bytes()) & 1
                != crate::hash::hash_bytes(first.as_bytes()) & 1
        })
        .unwrap();
    let valid = [
        padding.clone(),
        object("entry", &[0xc3], Some(ComdatKind::Any)),
        object(&second, &[0x90, 0xc3], Some(ComdatKind::Any)),
        object(&second, &[0xcc], Some(ComdatKind::Any)),
        object("entry", &[0xcc], Some(ComdatKind::Any)),
    ];
    let invalid = [
        padding,
        object("entry", &[0xc3], None),
        object(first, &[0xc3], Some(ComdatKind::NoDuplicates)),
        object(&second, &[0xc3], Some(ComdatKind::NoDuplicates)),
        object(&second, &[0xc3], Some(ComdatKind::NoDuplicates)),
        object(first, &[0xc3], Some(ComdatKind::NoDuplicates)),
    ];
    let mut previous_image = None;
    let mut previous_error = None;
    for threads in [1, 2, 16] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        let image = pool
            .install(|| {
                link_objects(&valid, |args| {
                    args.common.available_threads = std::num::NonZeroUsize::new(threads).unwrap();
                    args.directives.push(format!("/INCLUDE:{second}"));
                })
            })
            .unwrap();
        if let Some(previous) = &previous_image {
            assert_eq!(previous, &image);
        }
        previous_image = Some(image);
        let error = pool
            .install(|| {
                link_objects(&invalid, |args| {
                    args.common.available_threads = std::num::NonZeroUsize::new(threads).unwrap();
                })
            })
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("NODUPLICATES") && error.contains(&second),
            "{error}"
        );
        if let Some(previous) = &previous_error {
            assert_eq!(previous, &error);
        }
        previous_error = Some(error);
    }
}

#[test]
fn subsection_order_preserves_input_order_across_alignments() {
    let mut objects = vec![object("entry", &[0xc3], None)];
    for (name, value, alignment) in [
        (b".rdata$Z", 0x33, 1),
        (b".rdata$A", 0x11, 1),
        (b".rdata$A", 0x22, 64),
    ] {
        let mut o = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
        let section = o.add_section(Vec::new(), name.to_vec(), SectionKind::ReadOnlyData);
        o.append_section_data(section, &[value], alignment);
        objects.push(o.write().unwrap());
    }
    let image = link_objects(&objects, |a| {
        a.directives.push("/SECTION:.rdata,R".into());
    })
    .unwrap();
    let pe = object::read::pe::PeFile64::parse(&*image).unwrap();
    let section = pe.section_by_name(".rdata").unwrap();
    assert_eq!(
        section
            .data()
            .unwrap()
            .iter()
            .copied()
            .filter(|b| *b != 0)
            .collect::<Vec<_>>(),
        [0x11, 0x22, 0x33]
    );
}

#[test]
fn alternate_name_retries_a_previously_unresolved_archive_request() {
    let mut o = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let section = o.add_section(Vec::new(), b".drectve".to_vec(), SectionKind::Linker);
    o.append_section_data(section, b"/ALTERNATENAME:alias=actual", 1);
    let bytes = link_objects(
        &[
            caller("alias"),
            o.write().unwrap(),
            archive(&[object("actual", &[0xc3], None)]),
        ],
        |_| {},
    )
    .unwrap();
    assert!(object::read::pe::PeFile64::parse(&*bytes).is_ok());
}

#[test]
fn local_symbol_in_discarded_comdat_uses_selected_section_and_offset() {
    let mut o = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let section = o.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    o.append_section_data(section, &[0xcc, 0xcc], 16);
    o.section_symbol(section);
    let global = o.add_symbol(Symbol {
        name: b"selected".to_vec(),
        value: 0,
        size: 2,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(section),
        flags: SymbolFlags::None,
    });
    let local = o.add_symbol(Symbol {
        name: b"local".to_vec(),
        value: 1,
        size: 1,
        kind: SymbolKind::Text,
        scope: SymbolScope::Compilation,
        weak: false,
        section: SymbolSection::Section(section),
        flags: SymbolFlags::None,
    });
    o.add_comdat(Comdat {
        kind: ComdatKind::Any,
        symbol: global,
        sections: vec![section],
    });
    let data = o.add_section(Vec::new(), b".rdata".to_vec(), SectionKind::ReadOnlyData);
    o.append_section_data(data, &[0; 8], 8);
    o.add_relocation(
        data,
        Relocation {
            offset: 0,
            symbol: local,
            addend: 0,
            flags: RelocationFlags::Coff {
                typ: object::pe::IMAGE_REL_AMD64_ADDR64,
            },
        },
    )
    .unwrap();
    let image = link_objects(
        &[
            object("entry", &[0xc3], None),
            object("selected", &[0xc3, 0x90], Some(ComdatKind::Any)),
            o.write().unwrap(),
        ],
        |_| {},
    )
    .unwrap();
    let pe = object::read::pe::PeFile64::parse(&*image).unwrap();
    let pointer = u64::from_le_bytes(
        pe.section_by_name(".rdata").unwrap().data().unwrap()[..8]
            .try_into()
            .unwrap(),
    );
    let text = pe.section_by_name(".text").unwrap();
    assert_eq!(
        text.data().unwrap()[(pointer - text.address()) as usize],
        0x90
    );
}

#[test]
fn undefined_diagnostics_are_thread_count_independent() {
    let temp = tempfile::tempdir().unwrap();
    for (index, bytes) in [caller("missingZ"), renamed_caller("other", "missingA")]
        .into_iter()
        .enumerate()
    {
        std::fs::write(temp.path().join(format!("{index}.obj")), bytes).unwrap();
    }
    let mut expected = None;
    for threads in [1, 2, 4] {
        let mut args = CoffArgs::default();
        args.entry = Some("entry".into());
        args.common.output = Arc::from(temp.path().join("output.exe"));
        for index in 0..2 {
            args.common.inputs.push(Input {
                spec: InputSpec::File(temp.path().join(format!("{index}.obj")).into()),
                modifiers: Default::default(),
                search_first: None,
            });
        }
        let args = crate::Args::Coff(args);
        let error = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
            .install(|| crate::Linker::new().run(&args).err().unwrap().to_string());
        assert!(error.contains("missingA") && error.contains("missingZ"));
        if let Some(previous) = &expected {
            assert_eq!(&error, previous);
        } else {
            expected = Some(error);
        }
    }
}

#[test]
fn bigobj_raw_symbol_indices_include_auxiliary_entries() {
    let ordinary = caller("long_symbol_name");
    let file =
        object::read::coff::CoffFile::<_, object::pe::ImageFileHeader>::parse(&*ordinary).unwrap();
    let original = file.coff_header();
    let count = original.number_of_symbols.get(object::LittleEndian);
    let start = original.pointer_to_symbol_table.get(object::LittleEndian) as usize;
    let header = object::pe::AnonObjectHeaderBigobj {
        sig1: object::pe::IMAGE_FILE_MACHINE_UNKNOWN.into(),
        sig2: 0xffff.into(),
        version: 2.into(),
        machine: original.machine,
        time_date_stamp: original.time_date_stamp,
        class_id: object::pe::ANON_OBJECT_HEADER_BIGOBJ_CLASS_ID,
        size_of_data: 0.into(),
        flags: 0.into(),
        meta_data_size: 0.into(),
        meta_data_offset: 0.into(),
        number_of_sections: u32::from(original.number_of_sections.get(object::LittleEndian)).into(),
        pointer_to_symbol_table: (start as u32 + 36).into(),
        number_of_symbols: count.into(),
    };
    let mut bytes = object::pod::bytes_of(&header).to_vec();
    bytes.extend_from_slice(&ordinary[20..start]);
    for index in 0..original.number_of_sections.get(object::LittleEndian) as usize {
        for field in [20, 24, 28] {
            let offset = 56 + index * 40 + field;
            let pointer = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
            if pointer != 0 {
                bytes[offset..offset + 4].copy_from_slice(&(pointer + 36).to_le_bytes());
            }
        }
    }
    let mut auxiliaries = 0;
    for raw in ordinary[start..start + count as usize * 18].chunks_exact(18) {
        if auxiliaries != 0 {
            bytes.extend_from_slice(raw);
            bytes.extend_from_slice(&[0; 2]);
            auxiliaries -= 1;
        } else {
            bytes.extend_from_slice(&raw[..12]);
            bytes.extend_from_slice(
                &i32::from(i16::from_le_bytes(raw[12..14].try_into().unwrap())).to_le_bytes(),
            );
            bytes.extend_from_slice(&raw[14..]);
            auxiliaries = raw[17];
        }
    }
    bytes.extend_from_slice(&ordinary[start + count as usize * 18..]);
    assert_eq!(
        object::FileKind::parse(&*bytes).unwrap(),
        object::FileKind::CoffBig
    );
    let image = link_objects(&[bytes, object("long_symbol_name", &[0xc3], None)], |_| {}).unwrap();
    let pe = object::read::pe::PeFile64::parse(&*image).unwrap();
    assert_eq!(pe.entry(), pe.section_by_name(".text").unwrap().address());
}

#[test]
fn named_wholearchive_activates_an_already_parsed_member_without_exports() {
    let mut o = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let section = o.add_section(Vec::new(), b".rdata".to_vec(), SectionKind::ReadOnlyData);
    o.append_section_data(section, &[0x7f], 1);
    let image = link_objects(
        &[
            object("entry", &[0xc3], None),
            archive(&[o.write().unwrap()]),
        ],
        |a| {
            a.directives.push("/WHOLEARCHIVE:1.obj".into());
        },
    )
    .unwrap();
    let pe = object::read::pe::PeFile64::parse(&*image).unwrap();
    assert_eq!(
        pe.section_by_name(".rdata").unwrap().data().unwrap()[0],
        0x7f
    );
}

#[test]
fn unselected_archive_directives_do_not_add_libraries_or_mismatches() {
    let mut o = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let section = o.add_section(Vec::new(), b".drectve".to_vec(), SectionKind::Linker);
    o.append_section_data(
        section,
        b"/DEFAULTLIB:nonexistent /FAILIFMISMATCH:unused=bad",
        1,
    );
    let image = link_objects(
        &[
            caller("needed"),
            archive(&[object("needed", &[0xc3], None), o.write().unwrap()]),
        ],
        |a| {
            a.directives.push("/FAILIFMISMATCH:unused=good".into());
        },
    )
    .unwrap();
    assert!(object::read::pe::PeFile64::parse(&*image).is_ok());
}

#[test]
fn section_attributes_override_input_permissions_after_merging() {
    let mut o = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let section = o.add_section(Vec::new(), b".data$A".to_vec(), SectionKind::Data);
    o.append_section_data(section, &[0x42], 1);
    let image = link_objects(&[object("entry", &[0xc3], None), o.write().unwrap()], |a| {
        a.directives
            .extend(["/MERGE:.data=.rdata".into(), "/SECTION:.rdata,R".into()]);
    })
    .unwrap();
    let pe = object::read::pe::PeFile64::parse(&*image).unwrap();
    assert!(pe.section_by_name(".data").is_none());
    let object::SectionFlags::Coff { characteristics } =
        pe.section_by_name(".rdata").unwrap().flags()
    else {
        panic!("COFF flags expected");
    };
    assert!(!characteristics.contains(object::pe::IMAGE_SCN_MEM_WRITE));
    assert!(characteristics.contains(object::pe::IMAGE_SCN_MEM_READ));
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
    assert!(err.to_string().contains("Duplicate") && err.to_string().contains("entry"));
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
fn comdat_largest_and_newest_follow_selection_policy() {
    for (kind, first, second, expected) in [
        (ComdatKind::Largest, &[0xc3][..], &[0x90, 0xc3][..], 0x90),
        (ComdatKind::Largest, &[0x90, 0xc3][..], &[0xcc][..], 0x90),
        (ComdatKind::Newest, &[0xc3][..], &[0xcc][..], 0xcc),
    ] {
        let bytes = link_objects(
            &[
                object("entry", first, Some(kind)),
                object("entry", second, Some(kind)),
            ],
            |_| {},
        )
        .unwrap();
        let pe = object::read::pe::PeFile64::parse(&*bytes).unwrap();
        assert_eq!(
            pe.section_by_name(".text").unwrap().data().unwrap()[0],
            expected
        );
    }
}

#[test]
fn comdat_exact_match_and_no_duplicates_are_validated() {
    for kind in [ComdatKind::ExactMatch, ComdatKind::NoDuplicates] {
        assert!(
            link_objects(
                &[
                    object("entry", &[0xc3], Some(kind)),
                    object("entry", &[0xcc], Some(kind))
                ],
                |_| {}
            )
            .is_err()
        );
    }
    assert!(
        link_objects(
            &[
                object("entry", &[0xc3], Some(ComdatKind::ExactMatch)),
                object("entry", &[0xc3], Some(ComdatKind::ExactMatch))
            ],
            |_| {}
        )
        .is_ok()
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
    assert!(
        error.to_string().contains("Undefined") && error.to_string().contains("missing"),
        "{error:#?}"
    );
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
    assert!(error.to_string().contains("Duplicate") && error.to_string().contains("entry"));
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
    let bytes = link_objects(&[caller("builtin"), weak, archive], |_| {}).unwrap();
    let pe = object::read::pe::PeFile64::parse(&*bytes).unwrap();
    let code = pe.section_by_name(".text").unwrap().data().unwrap();
    assert!(!code.contains(&0xcc));
    let displacement = i32::from_le_bytes(code[1..5].try_into().unwrap());
    assert_eq!(code[(5 + displacement) as usize], 0xc3);
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
    use crate::fs::FileWriteMode;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("output.exe");
    let alias = temp.path().join("alias.exe");
    let input = temp.path().join("entry.obj");
    std::fs::write(&input, object("entry", &[0xc3], None)).unwrap();
    let original = vec![0x42; 1024 * 1024];
    for threads in [1, 2] {
        for mode in [
            FileReplacementMode::UnlinkAndReplace,
            FileReplacementMode::UpdateInPlace,
            FileReplacementMode::UpdateInPlaceWithFallback,
        ] {
            std::fs::write(&path, &original).unwrap();
            std::fs::hard_link(&path, &alias).unwrap();
            let mut args = CoffArgs::default();
            args.entry = Some("entry".into());
            args.common.output = Arc::from(path.as_path());
            args.common.file_replacement_mode = Some(mode);
            args.common.file_write_mode = Some(FileWriteMode::BufferThenWrite);
            args.common.available_threads = std::num::NonZeroUsize::new(threads).unwrap();
            args.common.inputs.push(Input {
                spec: InputSpec::File(input.clone().into()),
                modifiers: Default::default(),
                search_first: None,
            });
            let args = crate::Args::Coff(args);
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| crate::Linker::new().run(&args).map(drop))
                .unwrap();
            let image = std::fs::read(&path).unwrap();
            assert!(image.len() < original.len());
            assert!(object::read::pe::PeFile64::parse(&*image).is_ok());
            assert_eq!(
                std::fs::read(&alias).unwrap(),
                if mode == FileReplacementMode::UpdateInPlace {
                    image.as_slice()
                } else {
                    original.as_slice()
                }
            );
            std::fs::remove_file(&alias).unwrap();
        }
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
fn indexed_archive_selects_only_needed_member() {
    let members = [
        object("needed", &[0xc3], None),
        object("unused", &[0xcc], None),
    ];
    let bytes = link_objects(
        &[
            caller("needed"),
            indexed_archive(&members, &[("unused", 1), ("needed", 0)]),
        ],
        |_| {},
    )
    .unwrap();
    let pe = object::read::pe::PeFile64::parse(&*bytes).unwrap();
    let code = pe.section_by_name(".text").unwrap().data().unwrap();
    assert!(!code.contains(&0xcc));
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
    assert_eq!(args.common.default_thread_cap.get(), 16);
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
    let mut args = crate::Args::Coff(args);
    let mut expected = None;
    for threads in [1, 2, 4] {
        args.common_mut().num_threads = std::num::NonZeroUsize::new(threads);
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
            .install(|| crate::Linker::new().run(&args).map(drop))
            .unwrap();
        let image = std::fs::read(&args.common().output).unwrap();
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
        args.common_mut().num_threads = std::num::NonZeroUsize::new(threads);
        let error = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
            .install(|| crate::Linker::new().run(&args).map(drop))
            .unwrap_err()
            .to_string();
        assert!(error.contains("Unsupported x64 COFF relocation"));
        if let Some(previous) = &previous_error {
            assert_eq!(&error, previous);
        } else {
            previous_error = Some(error);
        }
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

#[test]
fn deferred_archive_body_is_validated_only_when_selected() {
    let mut invalid = pointer_object("unused", "entry", 1);
    let file =
        object::read::coff::CoffFile::<_, object::pe::ImageFileHeader>::parse(&*invalid).unwrap();
    let relocation = &file.sections().next().unwrap().coff_relocations().unwrap()[0];
    let offset =
        std::ptr::addr_of!(relocation.symbol_table_index) as usize - invalid.as_ptr() as usize;
    invalid[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let library = indexed_archive(&[invalid], &[("unused", 0)]);
    assert!(link_objects(&[object("entry", &[0xc3], None), library.clone()], |_| {}).is_ok());
    let error = link_objects(&[caller("unused"), library], |_| {}).unwrap_err();
    assert!(error.to_string().contains("Invalid relocation symbol"));
}

#[test]
fn archive_catalog_preserves_raw_symbol_indices_and_cached_hashes() {
    let bytes = pointer_object("needed", "entry", 1);
    let catalog = input::catalog(&bytes, "member.obj").unwrap().unwrap();
    let input::Parsed::Object(full) = input::parse(&bytes, "member.obj".into()).unwrap() else {
        panic!("Expected object");
    };
    assert_eq!(catalog.symbols.len(), full.symbols.len());
    for (index, symbol) in catalog.symbols.iter().enumerate() {
        if symbol.name.is_empty() {
            continue;
        }
        let expected = full.symbols[index];
        assert_eq!(symbol.name.range(), expected.name.range());
        assert_eq!(
            symbol.name_hash,
            crate::hash::hash_bytes(&bytes[symbol.name.range()])
        );
        assert_eq!(symbol.name_hash, expected.name_hash);
    }
}
