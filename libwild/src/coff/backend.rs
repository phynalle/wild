//! COFF adapters for the shared input, resolution and layout engines.
use crate::platform::{PreviousRelocationInfo, SourceInfo};
use linker_utils::elf::{DynamicRelocationKind, RelocationKindInfo};
use linker_utils::relaxation::{RelocationModifier, SectionRelaxDeltas};
pub(crate) struct CoffX64;
pub(crate) struct NoRelaxation;
impl platform::Relaxation for NoRelaxation {
    fn apply(&self, _: &mut [u8], _: &mut u64, _: &mut i64) {
        unreachable!("COFF does not use relocation relaxations")
    }
    fn rel_info(&self) -> RelocationKindInfo {
        unreachable!("COFF does not use relocation relaxations")
    }
    fn debug_kind(&self) -> impl std::fmt::Debug {
        "COFF (no relaxation)"
    }
    fn next_modifier(&self) -> RelocationModifier {
        unreachable!("COFF does not use relocation relaxations")
    }
    fn is_mandatory(&self) -> bool {
        false
    }
}
#[allow(unused_variables)]
impl platform::Arch for CoffX64 {
    type Platform = Coff;
    type Relaxation = NoRelaxation;
    fn arch_identifier() -> <Self::Platform as Platform>::ArchIdentifier {}
    fn get_dynamic_relocation_type(
        relocation: DynamicRelocationKind,
    ) -> <Self::Platform as Platform>::RelocationInfo {
        0
    }
    fn write_plt_entry(plt_entry: &mut [u8], got_address: u64, plt_address: u64) -> Result {
        bail!("COFF does not use ELF PLT entries")
    }
    fn relocation_from_raw(
        r_type: <Self::Platform as Platform>::RelocationInfo,
    ) -> Result<RelocationKindInfo> {
        bail!("Unsupported x64 COFF relocation {r_type}")
    }
    fn rel_type_to_string(
        r_type: <Self::Platform as Platform>::RelocationInfo,
    ) -> Cow<'static, str> {
        Cow::Owned(format!("COFF relocation {r_type}"))
    }
    fn tp_offset_start(layout: &Layout<Self::Platform>) -> u64 {
        0
    }
    fn get_property_class(property_type: u32) -> Option<crate::elf::PropertyClass> {
        None
    }
    fn merge_eflags(
        eflags: impl Iterator<Item = <Self::Platform as Platform>::FileFlags>,
    ) -> Result<<Self::Platform as Platform>::FileFlags> {
        Ok(())
    }
    fn high_part_relocations() -> &'static [<Self::Platform as Platform>::RelocationInfo] {
        &[]
    }
    fn get_source_info<'data>(
        object: &<Self::Platform as Platform>::File<'data>,
        relocations: &<Self::Platform as Platform>::RelocationSections,
        section: &<Self::Platform as Platform>::SectionHeader,
        offset_in_section: u64,
    ) -> Result<SourceInfo> {
        Ok(platform::SourceInfo(None))
    }
    fn new_relaxation(
        relocation_kind: <Self::Platform as Platform>::RelocationInfo,
        section_bytes: &[u8],
        offset_in_section: u64,
        flags: ValueFlags,
        output_kind: OutputKind,
        section_flags: <Self::Platform as Platform>::SectionFlags,
        relax_deltas: Option<&SectionRelaxDeltas>,
        sym_addr: u64,
        section_address: u64,
        rel_addend: i64,
        previous_relocation: Option<
            PreviousRelocationInfo<<Self::Platform as Platform>::RelocationInfo>,
        >,
    ) -> Option<Self::Relaxation> {
        None
    }
}
use crate::grouping::Group;
use crate::layout::{
    CommonGroupState, DynamicSymbolDefinition, Layout, ObjectLayoutState, OutputRecordLayout,
    PreludeLayoutState, SymbolResolutions,
};
use crate::layout_rules::SectionRule;
use crate::output_section_id::{CustomSectionIds, OutputOrder};
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::parsing::InternalSymDefInfo;
use crate::platform::SectionAttributes as _;
use crate::platform::{Arch, Platform, RelocationSequence as _};
use crate::program_segments::ProgramSegments;
use crate::resolution::UnloadedSection;
use crate::symbol_db::{SymbolDb, SymbolId};
use crate::value_flags::{AtomicPerSymbolFlags, ValueFlags};
use crate::{FileSystem, OutputKind, bail};
use rayon::Scope;
use rayon::prelude::*;
use std::num::NonZeroU32;

#[allow(unused_variables)]
impl platform::Platform for Coff {
    const BSS_SECTION_ID: Option<OutputSectionId> = Some(OutputSectionId::from_u32(3));
    fn section_identity_from_name<'data>(
        name: SectionName<'data>,
    ) -> Option<SectionIdentity<'data, Self>> {
        Some(SectionIdentity::new(name, ()))
    }
    type InputResolutionState = InputState;
    const CACHE_PREFERRED_SYMBOLS: bool = true;
    const BUCKET_SORTED_SECTIONS: bool = true;
    fn section_sort_rank(section: &Section) -> usize {
        section.layout_sort_rank.load(Ordering::Relaxed) as usize
    }
    fn entry_point<'a>(
        db: &'a SymbolDb<Self>,
        inferred: Option<&'a [u8]>,
    ) -> platform::EntryPoint<'a> {
        if let Some(entry) = &db.args.entry {
            return platform::EntryPoint::Symbol(entry.as_bytes());
        }
        let entry = inferred.unwrap_or_else(|| inferred_entry(db, |_| false));
        platform::EntryPoint::Symbol(entry)
    }
    fn preferred_symbol_candidate(
        db: &SymbolDb<Self>,
        first: SymbolId,
        alternatives: &[SymbolId],
    ) -> SymbolId {
        let rank = |id: SymbolId| {
            if let crate::grouping::SequencedInput::Object(object) =
                db.file(db.file_id_for_symbol(id))
            {
                let symbol = &object.parsed.object.symbols[id.to_input(object.symbol_id_range).0];
                let strength = if symbol.is_weak() {
                    0
                } else if symbol.as_common().is_some() {
                    1
                } else {
                    2
                };
                strength * 2 + u8::from(!object.is_optional())
            } else {
                5
            }
        };
        let mut winner = first;
        let mut priority = rank(first);
        if priority == 5 {
            return first;
        }
        for &id in alternatives {
            let next = rank(id);
            if next > priority {
                winner = id;
                priority = next;
            }
            if priority == 5 {
                break;
            }
        }
        winner
    }
    fn resolve_input_symbol<'data, 'scope>(
        object: &crate::grouping::SequencedInputObject<'data, Self>,
        _: object::SymbolIndex,
        symbol: &Symbol,
        definition: &mut SymbolId,
        resources: &'scope crate::resolution::ResolutionResources<'data, 'scope, Self>,
        scope: &Scope<'scope>,
    ) -> Result<bool> {
        let Some((fallback, _search)) = symbol.weak() else {
            return Ok(false);
        };
        let file = &object.parsed.object;
        let fallback_symbol = &file.symbols[fallback];
        if !fallback_symbol.is_undefined() {
            *definition = object
                .symbol_id_range
                .input_to_id(object::SymbolIndex(fallback));
        } else {
            let attributes = crate::resolution::SymbolAttributes {
                name_info: Name(
                    file.symbol_name(fallback_symbol)?,
                    Some(fallback_symbol.name_hash),
                ),
                is_local: false,
                default_visibility: false,
                is_weak: false,
            };
            crate::resolution::resolve_symbol(
                object
                    .symbol_id_range
                    .input_to_id(object::SymbolIndex(fallback)),
                &attributes,
                definition,
                resources,
                false,
                object.file_id,
                scope,
                false,
            )?;
        }
        Ok(true)
    }
    fn finalise_input_definitions<'data>(
        db: &mut SymbolDb<'data, Self>,
        groups: &[crate::resolution::ResolvedGroup<'data, Self>],
    ) -> Result {
        for group in groups {
            for file in &group.files {
                let crate::resolution::ResolvedFile::Object(object) = file else {
                    continue;
                };
                for (index, symbol) in object.common.object.symbols.iter().enumerate() {
                    if let Some((fallback, _)) = symbol.weak() {
                        let id = object
                            .common
                            .symbol_id_range
                            .input_to_id(object::SymbolIndex(index));
                        let selected = db.definition(id);
                        if selected == id {
                            let fallback = object
                                .common
                                .symbol_id_range
                                .input_to_id(object::SymbolIndex(fallback));
                            db.replace_definition(id, fallback);
                        }
                    }
                }
            }
        }
        db.flatten_definitions()
    }
    fn select_input_sections<'data>(
        db: &mut SymbolDb<'data, Self>,
        groups: &[crate::resolution::ResolvedGroup<'data, Self>],
    ) -> Result {
        let representatives = crate::timing_guard!("Select COMDAT representatives");
        let section_count: usize = groups
            .iter()
            .flat_map(|g| &g.files)
            .filter_map(|f| {
                if let crate::resolution::ResolvedFile::Object(object) = f {
                    Some(object.common.object)
                } else {
                    None
                }
            })
            .map(|f| f.sections.len())
            .sum();
        let shards = if section_count < 4096 {
            1
        } else {
            rayon::current_num_threads().min(16).next_power_of_two()
        };
        let mut candidates: Vec<Vec<_>> = (0..shards).map(|_| Vec::new()).collect();
        let mut files = Vec::new();
        for group in groups {
            for file in &group.files {
                let crate::resolution::ResolvedFile::Object(object) = file else {
                    continue;
                };
                let file = object.common.object;
                if file.import.is_some() {
                    for section in &file.sections {
                        section.excluded.store(true, Ordering::Relaxed);
                    }
                    continue;
                }
                files.push(object);
                let mut fallback_prefix = None;
                for (index, section) in file.sections.iter().enumerate() {
                    if section.selection == 0 || section.selection == 5 || section.should_exclude()
                    {
                        continue;
                    }
                    let key = if let Some(symbol) = section.representative {
                        Cow::Borrowed(file.symbol_name(&file.symbols[symbol as usize])?)
                    } else {
                        let prefix =
                            fallback_prefix.get_or_insert_with(|| object.common.input.to_string());
                        Cow::Owned(format!("{prefix}#{index}").into_bytes())
                    };
                    let hash = if section.representative.is_some() {
                        section.key_hash
                    } else {
                        crate::hash::hash_bytes(&key)
                    };
                    let key = crate::hash::PreHashed::new(key, hash);
                    candidates[hash as usize & (shards - 1)].push((
                        (files.len() - 1, index),
                        key,
                        file,
                        index,
                    ));
                }
            }
        }
        // Each key stays on one worker, with candidates in original input order.
        let results: Vec<_> = candidates
            .into_par_iter()
            .map(|candidates| {
                crate::verbose_timing_phase!("Select COMDAT shard", candidates = candidates.len());
                let mut selected: ComdatSelection<'data> = Default::default();
                selected.reserve(candidates.len());
                for (order, key, file, index) in candidates {
                    select_comdat_candidate(&mut selected, key, file, index)
                        .map_err(|error| (order, error))?;
                }
                Ok::<_, ((usize, usize), crate::error::Error)>(selected)
            })
            .collect();
        let mut selected = Vec::with_capacity(shards);
        let mut first_error = None;
        for result in results {
            match result {
                Ok(map) => selected.push(map),
                Err((order, error)) => {
                    if first_error.as_ref().is_none_or(|(old, _)| order < *old) {
                        first_error = Some((order, error));
                    }
                }
            }
        }
        if let Some((_, error)) = first_error {
            return Err(error);
        }
        drop(representatives);
        let ranges: std::collections::BTreeMap<usize, _> = files
            .iter()
            .map(|o| {
                (
                    o.common.object as *const File as usize,
                    o.common.symbol_id_range,
                )
            })
            .collect();
        crate::timing_phase!("Redirect discarded COMDAT symbols");
        for object in files {
            let file = object.common.object;
            let mut replacements = vec![None; file.sections.len()];
            for (index, section) in file.sections.iter().enumerate() {
                if section.selection == 0 || section.selection == 5 || !section.should_exclude() {
                    continue;
                }
                let key = if let Some(symbol) = section.representative {
                    Cow::Borrowed(file.symbol_name(&file.symbols[symbol as usize])?)
                } else {
                    Cow::Owned(format!("{}#{index}", object.common.input).into_bytes())
                };
                let hash = if section.representative.is_some() {
                    section.key_hash
                } else {
                    crate::hash::hash_bytes(&key)
                };
                let key = crate::hash::PreHashed::new(key, hash);
                let Some(&(winner, winner_index)) =
                    selected[hash as usize & (shards - 1)].get(&key)
                else {
                    continue;
                };
                let anchor = winner.sections[winner_index]
                    .anchor_symbol
                    .or(winner.sections[winner_index].representative)
                    .context("COMDAT has no section anchor")?;
                let range = ranges[&(winner as *const File as usize)];
                replacements[index] = Some(range.input_to_id(object::SymbolIndex(anchor as usize)));
            }
            for (index, symbol) in file.symbols.iter().enumerate() {
                if symbol.is_local() && symbol.section > 0 {
                    if let Some(target) = replacements[symbol.section as usize - 1] {
                        db.replace_definition_with_addend(
                            object
                                .common
                                .symbol_id_range
                                .input_to_id(object::SymbolIndex(index)),
                            target,
                            u64::from(symbol.value),
                        );
                    }
                }
            }
            for section in &file.sections {
                let mut parent = section.parent;
                let mut depth = 0;
                while let Some(index) = parent {
                    depth += 1;
                    crate::ensure!(depth <= file.sections.len(), "Associative COMDAT cycle");
                    let ancestor = &file.sections[index as usize];
                    if ancestor.should_exclude() {
                        section.excluded.store(true, Ordering::Relaxed);
                    }
                    parent = ancestor.parent;
                }
            }
        }
        Ok(())
    }
    fn definition_is_available<'data>(
        file: &File<'data>,
        symbol: &Symbol,
        _: object::SymbolIndex,
    ) -> bool {
        symbol.section <= 0
            || if file.deferred && file.materialized.get().is_none() {
                !file.catalog_excluded[symbol.section as usize - 1]
            } else {
                !file.sections[symbol.section as usize - 1].should_exclude()
            }
    }
    fn resolve_input_extensions<'data, F: FileSystem>(
        state: &mut InputState,
        db: &mut SymbolDb<'data, Self>,
        resolver: &mut crate::resolution::Resolver<'data, Self>,
        loader: &mut crate::input_data::FileLoader<'data, F>,
        flags: &mut crate::value_flags::PerSymbolFlags,
        sections: &mut OutputSections<'data, Self>,
        rules: &mut crate::layout_rules::LayoutRulesBuilder<'data>,
    ) -> Result<bool> {
        let mut changed = false;
        if !state.initialized {
            state.initialized = true;
            state.no_default_libraries = db.args.no_default_libraries;
            state.excluded.extend(
                db.args
                    .excluded_default_libraries
                    .iter()
                    .map(|s| library_key(s)),
            );
            state
                .pending
                .extend(db.args.default_libraries.iter().map(|s| (s.clone(), false)));
            for text in &db.args.directives {
                changed |= directive(state, db, text)?;
            }
            for file in &loader.loaded_files {
                if let Some(name) = file.filename.file_name().and_then(|n| n.to_str()) {
                    state.libraries.insert(library_key(name));
                }
            }
        }
        let mut texts = Vec::new();
        let mut has_tls = false;
        for id in &resolver.activated_files {
            if let crate::resolution::ResolvedFile::Object(object) =
                &resolver.resolved_groups[id.group()].files[id.file()]
            {
                if state.processed.insert(*id) {
                    texts.extend(object.common.object.directives.iter().cloned());
                    has_tls |= object.common.object.sections.iter().any(|s| {
                        &object.common.object.data[s.name.range()] == b".tls"
                            || object.common.object.data[s.name.range()].starts_with(b".tls$")
                    });
                }
            }
        }
        for text in texts {
            changed |= directive(state, db, &text)?;
        }
        if db.args.entry.is_none() {
            let entry = inferred_entry(db, |id| state.processed.contains(&id));
            changed |= db.entry_symbol_name() != Some(entry);
            db.set_inferred_entry(entry);
        }
        if state.whole_archive {
            for group in &db.groups {
                if let crate::grouping::Group::Objects(objects) = group {
                    for object in objects.iter() {
                        if object.parsed.input.has_archive_semantics() {
                            changed |= resolver.request_file(object.file_id);
                        }
                    }
                }
            }
        }
        if has_tls && !db.extra_required_symbols.contains(&b"_tls_used".as_slice()) {
            db.extra_required_symbols.push(b"_tls_used");
            changed = true;
        }
        let mut inputs = Vec::new();
        for (name, whole) in std::mem::take(&mut state.pending) {
            let key = library_key(&name);
            if !whole && (state.no_default_libraries || state.excluded.contains(&key)) {
                continue;
            }
            if !state.libraries.insert(key.clone()) {
                if whole {
                    for group in &db.groups {
                        if let crate::grouping::Group::Objects(objects) = group {
                            for object in objects.iter() {
                                if object.parsed.input.has_archive_semantics()
                                    && object
                                        .parsed
                                        .input
                                        .file
                                        .filename
                                        .file_name()
                                        .and_then(|n| n.to_str())
                                        .is_some_and(|n| library_key(n) == key)
                                {
                                    changed |= resolver.request_file(object.file_id);
                                }
                            }
                        }
                    }
                }
                continue;
            }
            let file_name = if name.to_ascii_lowercase().ends_with(".lib") {
                name
            } else {
                format!("{name}.lib")
            };
            let direct = std::path::PathBuf::from(&file_name);
            let path = if loader.file_system().file_type(&direct).is_ok() {
                direct
            } else {
                db.args
                    .lib_search_path
                    .iter()
                    .map(|p| p.join(&file_name))
                    .find(|p| loader.file_system().file_type(p).is_ok())
                    .with_context(|| format!("Couldn't find library {file_name}"))?
            };
            inputs.push(crate::args::Input {
                spec: crate::args::InputSpec::File(path.into_boxed_path()),
                search_first: None,
                modifiers: crate::args::Modifiers {
                    whole_archive: whole,
                    ..Default::default()
                },
            });
        }
        if !inputs.is_empty() {
            let loaded = loader.load_inputs::<Self>(&inputs, db.args, &mut None)?;
            db.add_inputs(flags, sections, rules, loaded)?;
            changed = true;
        }
        if !changed {
            if !state.imports_created {
                state.imports_created = true;
                let mut imports = Vec::new();
                for group in &resolver.resolved_groups {
                    for file in &group.files {
                        if let crate::resolution::ResolvedFile::Object(object) = file {
                            if let Some(import) = &object.common.object.import {
                                imports.push(import.clone());
                            }
                        }
                    }
                }
                if !imports.is_empty() {
                    let bytes = imports_object(&mut imports)?;
                    let data = db.herd.get().alloc_slice_copy(&bytes);
                    let object = File::parse_coff(data, "<PE imports>".into())?;
                    db.add_inputs(
                        flags,
                        sections,
                        rules,
                        crate::input_data::LoadedInputs {
                            objects: vec![Ok(Box::new(crate::parsing::ParsedInputObject {
                                input: crate::input_data::InputRef {
                                    file: crate::input_data::InputFileRef::synthetic(
                                        std::path::Path::new("<PE imports>"),
                                    ),
                                    data,
                                    entry: None,
                                },
                                object,
                                modifiers: Default::default(),
                            }))],
                            linker_scripts: Vec::new(),
                            stub_libraries: Vec::new(),
                            lto_objects: Vec::new(),
                        },
                    )?;
                    return Ok(true);
                }
            }
        }
        Ok(changed)
    }
    fn configure_input_layout<'data>(
        state: &InputState,
        db: &SymbolDb<'data, Self>,
        resolved: &[crate::resolution::ResolvedGroup<'data, Self>],
        sections: &mut OutputSections<'data, Self>,
        rules: &mut crate::layout_rules::LayoutRulesBuilder<'data>,
    ) -> Result {
        let allocator = db.herd.get();
        let batches: Vec<Result<hashbrown::HashMap<&[u8], (u32, u32)>>> = resolved
            .par_chunks(16)
            .map(|groups| {
                let mut names: hashbrown::HashMap<&[u8], (u32, u32)> = Default::default();
                for group in groups {
                    for file in &group.files {
                        if let crate::resolution::ResolvedFile::Object(object) = file {
                            if object.common.object.import.is_some() {
                                continue;
                            }
                            for (index, section) in object.common.object.enumerate_sections() {
                                if section.should_exclude() {
                                    continue;
                                }
                                let name = object.common.object.section_name(index)?;
                                let value = names.entry(name).or_insert((0, 1));
                                value.0 |= section.flags;
                                value.1 = value.1.max(section.alignment);
                            }
                        }
                    }
                }
                Ok(names)
            })
            .collect();
        let mut names: hashbrown::HashMap<&[u8], (u32, u32)> = Default::default();
        for batch in batches {
            for (name, (flags, alignment)) in batch? {
                let value = names.entry(name).or_insert((0, 1));
                value.0 |= flags;
                value.1 = value.1.max(alignment);
            }
        }
        let mut ordered_names: Vec<_> = names.into_iter().collect();
        ordered_names.sort_unstable_by_key(|(name, _)| *name);
        let names: hashbrown::HashMap<_, _> = ordered_names
            .iter()
            .enumerate()
            .map(|(rank, &(name, (_, alignment)))| Ok((name, (alignment, u32::try_from(rank)?))))
            .collect::<Result<_>>()?;
        let batches: Vec<Result> = resolved
            .par_chunks(16)
            .map(|groups| {
                for group in groups {
                    for file in &group.files {
                        if let crate::resolution::ResolvedFile::Object(object) = file {
                            for (index, section) in object.common.object.enumerate_sections() {
                                if section.should_exclude() {
                                    continue;
                                }
                                if let Some((alignment, rank)) =
                                    names.get(object.common.object.section_name(index)?)
                                {
                                    section
                                        .layout_alignment
                                        .store(*alignment, Ordering::Relaxed);
                                    section.layout_sort_rank.store(*rank, Ordering::Relaxed);
                                }
                                if state.attributes.is_empty() {
                                    continue;
                                }
                                let name = std::str::from_utf8(
                                    object
                                        .common
                                        .object
                                        .section_name(index)?
                                        .split(|b| *b == b'$')
                                        .next()
                                        .unwrap(),
                                )?;
                                let mut target = name;
                                for _ in 0..32 {
                                    if let Some(next) = state.merges.get(target) {
                                        target = next;
                                    } else {
                                        break;
                                    }
                                }
                                if let Some(bits) = state.attributes.get(target) {
                                    section.output_flags.store(
                                        (section.flags & !0xfe000000) | bits,
                                        Ordering::Relaxed,
                                    );
                                }
                            }
                        }
                    }
                }
                Ok(())
            })
            .collect();
        for result in batches {
            result?;
        }
        for (name, (flags, alignment)) in ordered_names {
            let base = std::str::from_utf8(name.split(|b| *b == b'$').next().unwrap_or(name))?;
            let mut target = base;
            let mut depth = 0;
            while let Some(next) = state.merges.get(target) {
                target = next;
                depth += 1;
                crate::ensure!(depth < 32, "Section merge cycle");
            }
            {
                let target = allocator.alloc_slice_copy(target.as_bytes());
                let primary = if target == b".bss" {
                    OutputSectionId::from_u32(3)
                } else {
                    sections.get_or_create_named_section(
                        SectionIdentity::new(SectionName(target), ()),
                        Alignment::new(1)?,
                        None,
                        None,
                        None,
                        Vec::new(),
                        None,
                    )
                };
                sections
                    .section_infos
                    .get_mut(primary)
                    .section_attributes
                    .merge(Attributes(flags & 0xfe0000e0));
                let id = if name.contains(&b'$') {
                    sections.add_secondary_section(
                        primary,
                        Alignment::new(alignment.into())?,
                        None,
                        None,
                    )
                } else {
                    primary
                };
                sections
                    .section_infos
                    .get_mut(id)
                    .section_attributes
                    .merge(Attributes(flags & 0xfe0000e0));
                rules.add_section_rule(SectionRule::new(
                    name,
                    None,
                    crate::layout_rules::SectionRuleOutcome::Section(
                        crate::layout_rules::SectionOutputInfo {
                            section_id: id,
                            must_keep: false,
                            sorted: true,
                        },
                    ),
                )?);
            }
        }
        let ids: Vec<_> = sections.section_infos.iter().map(|(id, _)| id).collect();
        for id in ids {
            let primary = sections.primary_output_section(id);
            if let Some(name) = sections.name(primary) {
                if let Some(bits) = state.attributes.get(std::str::from_utf8(name.0)?) {
                    let attributes = &mut sections.section_infos.get_mut(id).section_attributes;
                    attributes.0 = (attributes.0 & !0xfe000000) | bits;
                }
            }
        }
        Ok(())
    }
    fn finalise_output_section_alignments(
        _: &OutputSectionPartMap<u64>,
        sections: &mut OutputSections<Self>,
    ) {
    }
    fn last_part_size_to_extend(record: &OutputRecordLayout, _: PartId) -> Result<usize> {
        Ok(((record.file_end() + 511) & !511) - record.file_end())
    }
    fn prepare_object<'data>(
        file: &mut File<'data>,
        allocator: &bumpalo_herd::Member<'data>,
    ) -> Result {
        if let Some(import) = &file.contents.import {
            // Short imports expose names for archive selection; their real storage is synthesized
            // only after the shared resolver has selected the corresponding members.
            let name = import.symbol.as_bytes();
            let bytes = allocator.alloc_slice_fill_copy(14 + name.len() * 2, 0);
            bytes[..8].copy_from_slice(b".idata$5");
            bytes[8..8 + name.len()].copy_from_slice(name);
            bytes[8 + name.len()..14 + name.len()].copy_from_slice(b"__imp_");
            bytes[14 + name.len()..].copy_from_slice(name);
            file.data = bytes;
            let end = u32::try_from(8 + name.len())?;
            file.symbols = input::SymbolTable::Borrowed(allocator.alloc_slice_copy(&[
                Symbol {
                    name: input::ByteRange { start: 8, end },
                    name_hash: crate::hash::hash_bytes(name),
                    section: 1,
                    class: 2,
                    ..Default::default()
                },
                Symbol {
                    name: input::ByteRange {
                        start: end,
                        end: u32::try_from(bytes.len())?,
                    },
                    name_hash: crate::hash::hash_bytes(&bytes[end as usize..]),
                    section: 1,
                    class: 2,
                    ..Default::default()
                },
            ]));
            file.sections = SectionTable::Borrowed(allocator.alloc_slice_fill_iter([Section {
                name: input::ByteRange { start: 0, end: 8 },
                data: Default::default(),
                size: 0,
                alignment: 1,
                layout_alignment: std::sync::atomic::AtomicU32::new(1),
                layout_sort_rank: std::sync::atomic::AtomicU32::new(0),
                flags: 0xc0000040,
                output_flags: std::sync::atomic::AtomicU32::new(0xc0000040),
                selection: 0,
                parent: None,
                representative: None,
                key_hash: 0,
                anchor_symbol: None,
                relocations: Default::default(),
                excluded: AtomicBool::new(false),
                retain: false,
            }]));
            // Import placeholders have no associative edges and are discarded before GC.
        }
        Ok(())
    }
    fn is_allowed_in_archive(kind: crate::file_kind::FileKind) -> bool {
        matches!(
            kind,
            crate::file_kind::FileKind::CoffObject
                | crate::file_kind::FileKind::CoffBigObject
                | crate::file_kind::FileKind::CoffImport
        )
    }
    const NUM_SINGLE_PART_SECTIONS: u32 = 3;
    const NUM_BUILT_IN_REGULAR_SECTIONS: usize = 1;
    const DEFAULT_FILE_REPLACEMENT_MODE: crate::FileReplacementMode =
        crate::FileReplacementMode::UnlinkAndReplace;
    type File<'data> = File<'data>;
    type FileFlags = ();
    type SymtabEntry = Symbol;
    type PlatformSpecificSymbol = core::convert::Infallible;
    type SectionHeader = Section;
    type SectionFlags = Flags;
    type SectionAttributes = Attributes;
    type SectionType = SectionType;
    type SegmentType = ();
    type ProgramSegmentDef = Segment;
    type BuiltInSectionDetails = BuiltIn;
    type RelocationSections = ();
    type DynamicEntry = ();
    type DynamicSymbolDefinitionExt = ();
    type RelocationInfo = u16;
    type NonAddressableIndexes = Indexes;
    type NonAddressableCounts = ();
    type EpilogueLayoutExt = ();
    type GroupLayoutExt = ();
    type CommonGroupStateExt = ();
    type StubLibraryLayoutStateExt = ();
    type StubLibraryLayoutExt = ();
    type ArchIdentifier = ();
    type Args = CoffArgs;
    type ResolutionExt = ();
    type SymtabShndxEntry = ();
    type SymbolVersionIndex = ();
    type FinaliseSizesExt<'data> = FinalSizes;
    type LayoutExt<'data> = FinalSizes;
    type GdbIndexScanResult<'data> = ();
    type SectionIterator<'a> = std::slice::Iter<'a, Section>;
    type DynamicTagValues<'data> = DynamicTags;
    type RelocationList<'data> = Relocations<'data>;
    type DynamicLayoutStateExt<'data> = ();
    type DynamicLayoutExt<'data> = ();
    type LayoutResourcesExt<'data> = ();
    type PreludeLayoutStateExt = ();
    type PreludeLayoutExt = ();
    type ObjectLayoutStateExt<'data> = ();
    type RawSymbolName<'data> = Name<'data>;
    type VersionNames<'data> = ();
    type VerneedTable<'data> = Versions;
    type ResolvedObjectExt<'data> = ();
    type GcUnit = layout::SectionGcUnit;
    type SectionIdentityExt = ();

    fn write_output_file<'data, A: Arch<Platform = Self>, F: FileSystem>(
        output: &crate::file_writer::Output<F>,
        layout: &Layout<'data, Self>,
    ) -> Result {
        output.write(layout, super::pe_writer::write)
    }
    fn section_attributes(header: &Self::SectionHeader) -> Self::SectionAttributes {
        Attributes(header.output_flags.load(Ordering::Relaxed) & 0xfe0000e0)
    }
    fn apply_force_keep_sections(keep_sections: &mut OutputSectionMap<bool>, args: &Self::Args) {}
    fn is_zero_sized_section_content(section_id: OutputSectionId) -> bool {
        true
    }
    fn built_in_section_details() -> &'static [Self::BuiltInSectionDetails] {
        &[]
    }
    fn finalise_group_layout(memory_offsets: &OutputSectionPartMap<u64>) -> Self::GroupLayoutExt {}
    fn frame_data_base_address(memory_offsets: &OutputSectionPartMap<u64>) -> u64 {
        0
    }
    fn align_load_segment_start(
        _segment_def: Self::ProgramSegmentDef,
        segment_alignment: Alignment,
        file_offset: &mut usize,
        mem_offset: &mut u64,
    ) {
        *file_offset = Alignment::new(512).unwrap().align_up(*file_offset as u64) as usize;
        *mem_offset = Alignment::new(4096).unwrap().align_up(*mem_offset);
    }
    fn activate_dynamic<'data>(
        state: &mut layout::DynamicLayoutState<'data, Self>,
        common: &mut CommonGroupState<'data, Self>,
    ) {
    }
    fn pre_finalise_sizes_prelude<'scope, 'data>(
        prelude: &mut layout::PreludeLayoutState<'data, Self>,
        common: &mut layout::CommonGroupState<'data, Self>,
        resources: &layout::GraphResources<'data, 'scope, Self>,
    ) {
    }
    fn finalise_sizes_dynamic<'data>(
        object: &mut layout::DynamicLayoutState<'data, Self>,
        common: &mut layout::CommonGroupState<'data, Self>,
    ) -> Result {
        Ok(())
    }
    fn finalise_object_sizes<'data>(
        object: &mut layout::ObjectLayoutState<'data, Self>,
        common: &mut layout::CommonGroupState<'data, Self>,
    ) {
    }
    fn finalise_object_layout<'data>(
        object: &layout::ObjectLayoutState<'data, Self>,
        memory_offsets: &mut OutputSectionPartMap<u64>,
    ) {
    }
    fn finalise_layout_dynamic<'data>(
        state: &mut layout::DynamicLayoutState<'data, Self>,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resources: &layout::FinaliseLayoutResources<'_, 'data, Self>,
        resolutions_out: &mut layout::ResolutionWriter<Self>,
    ) -> Result<Option<Self::DynamicLayoutExt<'data>>> {
        Ok(None)
    }
    fn take_dynsym_index(
        memory_offsets: &mut OutputSectionPartMap<u64>,
        section_layouts: &OutputSectionMap<OutputRecordLayout>,
    ) -> Result<u32> {
        bail!("COFF dynamic symbol tables are unsupported")
    }
    fn compute_object_addresses<'data>(
        object: &layout::ObjectLayoutState<'data, Self>,
        memory_offsets: &mut OutputSectionPartMap<u64>,
    ) {
    }
    fn layout_resources_ext<'data>(
        groups: &[Group<'data, Self>],
    ) -> Self::LayoutResourcesExt<'data> {
    }
    fn gc_unit_for_symbol<'data>(
        object: &Self::File<'data>,
        symbol: &Self::SymtabEntry,
        symbol_index: object::SymbolIndex,
    ) -> Result<Option<Self::GcUnit>> {
        Ok(object
            .symbol_section(symbol, symbol_index)?
            .map(layout::SectionGcUnit::new))
    }
    fn activate_object_gc<'data, 'scope, A: Arch<Platform = Self>>(
        object: &mut layout::ObjectLayoutState<'data, Self>,
        common: &mut layout::CommonGroupState<'data, Self>,
        resources: &'scope layout::GraphResources<'data, 'scope, Self>,
        queue: &mut layout::LocalWorkQueue<Self>,
        scope: &Scope<'scope>,
    ) -> Result {
        object.activate_section_gc::<A>(common, resources, queue, scope)
    }
    fn load_gc_unit<'data, 'scope, A: Arch<Platform = Self>>(
        object: &mut layout::ObjectLayoutState<'data, Self>,
        common: &mut layout::CommonGroupState<'data, Self>,
        resources: &'scope layout::GraphResources<'data, 'scope, Self>,
        queue: &mut layout::LocalWorkQueue<Self>,
        unit: Self::GcUnit,
        scope: &Scope<'scope>,
    ) -> Result {
        let index = unit.section_index();
        object.handle_section_load_request::<A>(common, resources, queue, index, scope)?;
        let children = &object.object.children
            [object.object.child_offsets[index.0]..object.object.child_offsets[index.0 + 1]];
        for &child in children {
            if !object.object.sections[child].should_exclude() {
                queue.send_gc_unit_request::<A>(
                    object.file_id,
                    layout::SectionGcUnit::new(object::SectionIndex(child)),
                    resources,
                    scope,
                );
            }
        }
        Ok(())
    }
    fn load_object_section_relocations<'data, 'scope, A: Arch<Platform = Self>>(
        state: &mut layout::ObjectLayoutState<'data, Self>,
        common: &mut layout::CommonGroupState<'data, Self>,
        queue: &mut layout::LocalWorkQueue<Self>,
        resources: &'scope layout::GraphResources<'data, '_, Self>,
        section: layout::Section,
        section_index: object::SectionIndex,
        scope: &Scope<'scope>,
    ) -> Result {
        for relocation in state.object.relocations(section_index, &())?.rel_iter() {
            if relocation.kind == 0 {
                continue;
            }
            let local = state
                .symbol_id_range
                .input_to_id(object::SymbolIndex(relocation.symbol as usize));
            let target = resources.symbol_db.definition(local);
            let flags = resources.per_symbol_flags.get_atomic(target);
            let old = flags.fetch_or(ValueFlags::DIRECT);
            layout::check_for_undefined::<A>(
                state,
                state.object.section(section_index)?,
                u64::from(relocation.offset),
                object::SymbolIndex(relocation.symbol as usize),
                old | ValueFlags::DIRECT,
                target,
                resources,
            )?;
            if !old.contains(ValueFlags::DIRECT) {
                queue.send_symbol_request::<A>(target, resources, scope);
            }
        }
        Ok(())
    }
    fn create_dynamic_symbol_definition<'data>(
        symbol_db: &SymbolDb<'data, Self>,
        symbol_id: SymbolId,
    ) -> Result<layout::DynamicSymbolDefinition<'data, Self>> {
        Ok(layout::DynamicSymbolDefinition {
            symbol_id,
            name: symbol_db.symbol_name(symbol_id)?.bytes(),
            format_specific: (),
        })
    }
    fn update_segment_keep_list(
        program_segments: &ProgramSegments<Self::ProgramSegmentDef>,
        keep_segments: &mut [bool],
        args: &Self::Args,
    ) {
    }
    fn program_segment_defs() -> &'static [Self::ProgramSegmentDef] {
        &[]
    }
    fn unconditional_segment_defs() -> &'static [Self::ProgramSegmentDef] {
        &[]
    }
    fn program_segment_should_include_section(
        segment_def: Self::ProgramSegmentDef,
        section_info: &crate::output_section_id::SectionOutputInfo<Self>,
        section_id: OutputSectionId,
        rosegment: bool,
    ) -> bool {
        segment_def.section == section_id
    }
    fn create_linker_defined_symbols(
        symbols: &mut crate::parsing::InternalSymbolsBuilder<Self>,
        output_kind: OutputKind,
        args: &Self::Args,
    ) {
        symbols
            .section_start(crate::output_section_id::FILE_HEADER, "__ImageBase")
            .hide();
    }
    fn built_in_section_infos<'data>()
    -> Vec<crate::output_section_id::SectionOutputInfo<'data, Self>> {
        (0..4)
            .map(|index| crate::output_section_id::SectionOutputInfo {
                section_attributes: Attributes(if index == 2 {
                    0x42000040
                } else if index == 3 {
                    0xc0000080
                } else {
                    0x40000040
                }),
                kind: crate::layout_rules::SectionKind::Primary(SectionIdentity::new(
                    SectionName(if index == 2 {
                        b".reloc"
                    } else if index == 3 {
                        b".bss"
                    } else {
                        b""
                    }),
                    (),
                )),
                min_alignment: Alignment::new(1).unwrap(),
                location_info: None,
                secondary_order: None,
                region_name: None,
                fill: None,
                phdrs: Vec::new(),
            })
            .collect()
    }
    fn create_finalise_sizes_ext<'data, 'states, 'files, A: Arch<Platform = Self>>(
        args: &Self::Args,
        groups: &'files mut [layout::GroupState<'data, Self>],
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) -> Result<Self::FinaliseSizesExt<'data>>
    where
        'data: 'files,
        'data: 'states,
    {
        let mut relocations = 0;
        for group in groups {
            for file in &group.files {
                if let layout::FileLayoutState::Object(object) = file {
                    for (index, section) in object.object.enumerate_sections() {
                        if matches!(
                            object.sections[index.0],
                            crate::resolution::SectionSlot::Loaded(_)
                                | crate::resolution::SectionSlot::Sorted(_)
                        ) {
                            relocations += object
                                .object
                                .relocations(index, &())?
                                .rel_iter()
                                .filter(|r| r.kind == 1 || r.kind == 2)
                                .count();
                        }
                    }
                }
            }
        }
        Ok(FinalSizes {
            base_relocations: relocations,
        })
    }
    fn create_layout_ext<'data>(
        finalise_sizes_ext: Self::FinaliseSizesExt<'data>,
        _resolutions: &SymbolResolutions<Self>,
        _group_layouts: &[layout::GroupLayout<'data, Self>],
    ) -> Result<Self::LayoutExt<'data>> {
        Ok(finalise_sizes_ext)
    }
    fn load_exception_frame_data<'data, 'scope, A: Arch<Platform = Self>>(
        object: &mut ObjectLayoutState<'data, Self>,
        common: &mut layout::CommonGroupState<'data, Self>,
        eh_frame_section_index: object::SectionIndex,
        resources: &'scope layout::GraphResources<'data, '_, Self>,
        queue: &mut layout::LocalWorkQueue<Self>,
        scope: &Scope<'scope>,
    ) -> Result {
        Ok(())
    }
    fn non_empty_section_loaded<'data, 'scope, A: Arch<Platform = Self>>(
        object: &mut layout::ObjectLayoutState<'data, Self>,
        common: &mut layout::CommonGroupState<'data, Self>,
        queue: &mut layout::LocalWorkQueue<Self>,
        unloaded: UnloadedSection,
        resources: &'scope layout::GraphResources<'data, 'scope, Self>,
        scope: &Scope<'scope>,
    ) -> Result {
        Ok(())
    }
    fn new_epilogue_layout<'data>(
        args: &Self::Args,
        output_kind: OutputKind,
        dynamic_symbol_definitions: &mut [DynamicSymbolDefinition<'data, Self>],
        group_states: &[layout::GroupState<'data, Self>],
    ) -> Self::EpilogueLayoutExt {
    }
    fn apply_non_addressable_indexes_epilogue(
        counts: &mut Self::NonAddressableCounts,
        state: &mut Self::EpilogueLayoutExt,
    ) {
    }
    fn apply_non_addressable_indexes<'data, 'groups>(
        symbol_db: &SymbolDb<'data, Self>,
        counts: &Self::NonAddressableCounts,
        mem_sizes_iter: impl Iterator<Item = &'groups mut OutputSectionPartMap<u64>>,
    ) {
    }
    fn finalise_sizes_epilogue<'data>(
        state: &mut Self::EpilogueLayoutExt,
        mem_sizes: &mut OutputSectionPartMap<u64>,
        dynamic_symbol_definitions: &[DynamicSymbolDefinition<'data, Self>],
        format_specific: &Self::FinaliseSizesExt<'data>,
        symbol_db: &SymbolDb<'data, Self>,
    ) -> Result<()> {
        *mem_sizes.get_mut(PartId::from_u32(2)) += format_specific.base_relocations as u64 * 12;
        Ok(())
    }
    fn finalise_sizes_all<'data>(
        mem_sizes: &mut OutputSectionPartMap<u64>,
        symbol_db: &SymbolDb<'data, Self>,
    ) {
    }
    fn finalise_layout_epilogue<'data>(
        epilogue_state: &mut Self::EpilogueLayoutExt,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        symbol_db: &SymbolDb<'data, Self>,
        common_state: &Self::FinaliseSizesExt<'data>,
        dynsym_start_index: u32,
        dynamic_symbol_defs: &[DynamicSymbolDefinition<Self>],
    ) -> Result {
        memory_offsets.increment(
            PartId::from_u32(2),
            common_state.base_relocations as u64 * 12,
        );
        Ok(())
    }
    fn is_symbol_non_interposable<'data>(
        object: &Self::File<'data>,
        args: &Self::Args,
        sym: &Self::SymtabEntry,
        output_kind: OutputKind,
        export_list: Option<&crate::export_list::ExportList>,
        lib_name: &[u8],
        archive_semantics: bool,
        is_undefined: bool,
    ) -> bool {
        true
    }
    fn allocate_header_sizes<'data>(
        prelude: &mut PreludeLayoutState<'data, Self>,
        sizes: &mut OutputSectionPartMap<u64>,
        header_info: &layout::HeaderInfo,
        program_segments: &ProgramSegments<Self::ProgramSegmentDef>,
        output_sections: &OutputSections<Self>,
        resources: &layout::FinaliseSizesResources<'data, '_, Self>,
        args: &Self::Args,
    ) {
        *sizes.get_mut(crate::part_id::FILE_HEADER) = Alignment::new(4096)
            .unwrap()
            .align_up(0x188 + u64::from(header_info.num_output_sections_with_content) * 40);
    }
    fn finalise_sizes_for_symbol<'data>(
        common: &mut CommonGroupState<'data, Self>,
        symbol_db: &SymbolDb<'data, Self>,
        symbol_id: SymbolId,
        flags: ValueFlags,
    ) -> Result {
        Ok(())
    }
    fn allocate_resolution(
        flags: ValueFlags,
        mem_sizes: &mut OutputSectionPartMap<u64>,
        output_kind: OutputKind,
        args: &Self::Args,
    ) {
    }
    fn allocate_object_symtab_space<'data>(
        state: &ObjectLayoutState<'data, Self>,
        common: &mut CommonGroupState<'data, Self>,
        symbol_db: &SymbolDb<'data, Self>,
        per_symbol_flags: &AtomicPerSymbolFlags,
    ) -> Result {
        Ok(())
    }
    fn allocate_internal_symbol(
        symbol_id: SymbolId,
        def_info: &InternalSymDefInfo<Self>,
        sizes: &mut OutputSectionPartMap<u64>,
        symbol_db: &SymbolDb<Self>,
    ) -> Result {
        Ok(())
    }
    fn allocate_prelude(common: &mut CommonGroupState<Self>, symbol_db: &SymbolDb<Self>) {}
    fn finalise_prelude_layout<'data>(
        prelude: &layout::PreludeLayoutState<Self>,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resources: &layout::FinaliseLayoutResources<'_, 'data, Self>,
    ) -> Result<Self::PreludeLayoutExt> {
        memory_offsets.increment(
            crate::part_id::FILE_HEADER,
            resources
                .section_layouts
                .get(crate::output_section_id::FILE_HEADER)
                .mem_size,
        );
        Ok(())
    }
    fn create_resolution(
        flags: ValueFlags,
        raw_value: u64,
        dynamic_symbol_index: Option<NonZeroU32>,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        args: &Self::Args,
        output_kind: OutputKind,
    ) -> layout::Resolution<Self> {
        layout::Resolution {
            raw_value,
            dynamic_symbol_index,
            format_specific: (),
            flags,
        }
    }
    fn raw_symbol_name<'data>(
        name_bytes: &'data [u8],
        verneed_table: &Self::VerneedTable<'data>,
        symbol_index: object::SymbolIndex,
    ) -> Self::RawSymbolName<'data> {
        Name(name_bytes, None)
    }
    fn default_layout_rules(args: &Self::Args) -> Vec<SectionRule<'static>> {
        Vec::new()
    }
    fn build_output_order_and_program_segments<'data>(
        custom: &CustomSectionIds,
        output_kind: OutputKind,
        output_sections: &OutputSections<'data, Self>,
        secondary: &OutputSectionMap<Vec<OutputSectionId>>,
        location_counters: &[crate::layout_rules::LocationCounter<'data>],
    ) -> (OutputOrder<'data>, ProgramSegments<Self::ProgramSegmentDef>) {
        let segments = output_sections
            .ids_with_info()
            .filter(|(id, _)| id.as_u32() != 0 && output_sections.merge_target(*id).is_none())
            .map(|(section, info)| Segment {
                section,
                attributes: info.section_attributes,
            })
            .collect();
        let mut builder = crate::output_section_id::OutputOrderBuilder::<Self>::new(
            segments,
            output_kind,
            output_sections,
            secondary,
            false,
            location_counters,
        );
        builder.add_section(crate::output_section_id::FILE_HEADER);
        let mut ids: Vec<_> = output_sections
            .ids_with_info()
            .filter(|(id, _)| id.as_u32() >= 3 && output_sections.merge_target(*id).is_none())
            .collect();
        ids.sort_by_key(|(id, _)| output_sections.name(*id).map(|n| n.0).unwrap_or_default());
        for (id, _) in ids {
            builder.add_section(id);
        }
        builder.add_section(OutputSectionId::from_u32(2));
        builder.build()
    }
    fn default_symtab_entry() -> Self::SymtabEntry {
        Symbol::default()
    }
    fn section_identity<'data>(
        name: SectionName<'data>,
        section: &Self::SectionHeader,
    ) -> SectionIdentity<'data, Self> {
        let name = SectionName(name.0.split(|b| *b == b'$').next().unwrap_or(name.0));
        SectionIdentity::new(name, ())
    }
}
use super::input;
use crate::alignment::Alignment;
use crate::args::coff::CoffArgs;
use crate::error::{Context, Result};
use crate::layout;
use crate::output_section_id::{OutputSectionId, OutputSections, SectionIdentity, SectionName};
use crate::part_id::PartId;
use crate::platform::{self, ObjectFile as _, SectionHeader as _, Symbol as _};
use crate::symbol_db::Visibility;
use object::pe;
use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Coff;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Segment {
    section: OutputSectionId,
    attributes: Attributes,
}

impl std::fmt::Display for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PE section {}", self.section.as_u32())
    }
}

impl platform::ProgramSegmentDef for Segment {
    fn is_writable(self) -> bool {
        self.attributes.0 & 0x80000000 != 0
    }
    fn is_executable(self) -> bool {
        self.attributes.0 & 0x20000000 != 0
    }
    fn always_keep(self) -> bool {
        self.section == crate::output_section_id::FILE_HEADER
    }
    fn is_loadable(self) -> bool {
        true
    }
    fn is_stack(self) -> bool {
        false
    }
    fn is_tls(self) -> bool {
        false
    }
    fn order_key(self) -> usize {
        self.section.as_usize()
    }
}

#[derive(Default)]
pub(crate) struct InputState {
    initialized: bool,
    processed: std::collections::BTreeSet<crate::input_data::FileId>,
    libraries: std::collections::BTreeSet<String>,
    excluded: std::collections::BTreeSet<String>,
    no_default_libraries: bool,
    whole_archive: bool,
    imports_created: bool,
    pending: Vec<(String, bool)>,
    mismatch: std::collections::BTreeMap<String, String>,
    merges: std::collections::BTreeMap<String, String>,
    attributes: std::collections::BTreeMap<String, u32>,
}

fn library_key(name: &str) -> String {
    name.to_ascii_lowercase()
        .strip_suffix(".lib")
        .unwrap_or(&name.to_ascii_lowercase())
        .to_owned()
}

fn inferred_entry(
    db: &SymbolDb<Coff>,
    selected: impl Fn(crate::input_data::FileId) -> bool,
) -> &'static [u8] {
    for (name, entry) in [
        (b"wmain".as_slice(), b"wmainCRTStartup".as_slice()),
        (b"WinMain".as_slice(), b"WinMainCRTStartup".as_slice()),
    ] {
        if db
            .get_unversioned_matching(
                &crate::symbol::UnversionedSymbolName::prehashed(name),
                |id| {
                    if let crate::grouping::SequencedInput::Object(object) =
                        db.file(db.file_id_for_symbol(id))
                    {
                        !object.is_optional() || selected(object.file_id)
                    } else {
                        false
                    }
                },
            )
            .is_some()
        {
            return entry;
        }
    }
    b"mainCRTStartup"
}

fn directive(state: &mut InputState, db: &mut SymbolDb<Coff>, text: &str) -> Result<bool> {
    let text = text.trim_start_matches(['/', '-']);
    let (name, value) = text.split_once(':').unwrap_or((text, ""));
    match name.to_ascii_lowercase().as_str() {
        "defaultlib" => state.pending.push((value.into(), false)),
        "nodefaultlib" => {
            if value.is_empty() {
                state.no_default_libraries = true;
            } else {
                state.excluded.insert(library_key(value));
            }
        }
        "include" => {
            if !db.extra_required_symbols.contains(&value.as_bytes()) {
                db.extra_required_symbols
                    .push(db.herd.get().alloc_slice_copy(value.as_bytes()));
                return Ok(true);
            }
        }
        "alternatename" => {
            let (from, to) = value.split_once('=').context("Invalid /ALTERNATENAME")?;
            return db.add_fallback_alias(from, to);
        }
        "failifmismatch" => {
            let (key, value) = value.split_once('=').context("Invalid /FAILIFMISMATCH")?;
            if let Some(old) = state.mismatch.insert(key.into(), value.into()) {
                crate::ensure!(old == value, "/FAILIFMISMATCH {key}: {old} vs {value}");
            }
        }
        "merge" => {
            let (a, b) = value.split_once('=').context("Invalid /MERGE")?;
            state.merges.insert(a.into(), b.into());
        }
        "section" => {
            let (name, flags) = value.split_once(',').context("Invalid /SECTION")?;
            let mut bits = 0;
            for flag in flags.to_ascii_uppercase().bytes() {
                bits |= match flag {
                    b'E' => 0x20000000,
                    b'R' => 0x40000000,
                    b'W' => 0x80000000,
                    b'D' => 0x02000000,
                    b'S' => 0x10000000,
                    b'K' => 0x04000000,
                    b'P' => 0x08000000,
                    b'N' | b'!' => 0,
                    _ => bail!("Invalid /SECTION attributes"),
                };
            }
            state.attributes.insert(name.into(), bits);
        }
        "wholearchive" => {
            if value.is_empty() {
                state.whole_archive = true;
            } else {
                state.pending.push((value.into(), true));
            }
        }
        "editandcontinue" | "disallowlib" => {}
        _ => bail!("Unsupported COFF directive /{text}"),
    }
    Ok(false)
}

pub(crate) struct FinalSizes {
    pub base_relocations: usize,
}

type ComdatSelection<'data> =
    crate::hash::PassThroughHashMap<Cow<'data, [u8]>, (&'data File<'data>, usize)>;

fn select_comdat_candidate<'data>(
    selected: &mut ComdatSelection<'data>,
    key: crate::hash::PreHashed<Cow<'data, [u8]>>,
    file: &'data File<'data>,
    index: usize,
) -> Result {
    let mut entry = match selected.entry(key) {
        hashbrown::hash_map::Entry::Vacant(entry) => {
            entry.insert((file, index));
            return Ok(());
        }
        hashbrown::hash_map::Entry::Occupied(entry) => entry,
    };
    let &(old_file, old_index) = entry.get();
    let old = &old_file.sections[old_index];
    let section = &file.sections[index];
    let replace = match section.selection {
        1 => bail!(
            "Duplicate NODUPLICATES COMDAT {}",
            String::from_utf8_lossy(entry.key())
        ),
        2 => false,
        3 => {
            crate::ensure!(
                old.size == section.size,
                "COMDAT size mismatch: {}",
                String::from_utf8_lossy(entry.key())
            );
            false
        }
        4 => {
            let same = old_file.raw_section_data(old)? == file.raw_section_data(section)?
                && old.size == section.size
                && old.relocations.len() == section.relocations.len()
                && old_file
                    .relocations(object::SectionIndex(old_index), &())?
                    .rel_iter()
                    .zip(
                        file.relocations(object::SectionIndex(index), &())?
                            .rel_iter(),
                    )
                    .all(|(a, b)| {
                        a.offset == b.offset
                            && a.kind == b.kind
                            && old_file
                                .symbol_name(&old_file.symbols[a.symbol as usize])
                                .ok()
                                == file.symbol_name(&file.symbols[b.symbol as usize]).ok()
                    });
            crate::ensure!(
                same,
                "COMDAT content mismatch: {}",
                String::from_utf8_lossy(entry.key())
            );
            false
        }
        6 => section.size > old.size,
        7 => true,
        selection => bail!("Unsupported COMDAT selection {selection}"),
    };
    if replace {
        old.excluded.store(true, Ordering::Relaxed);
        entry.insert((file, index));
    } else {
        section.excluded.store(true, Ordering::Relaxed);
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct File<'data> {
    pub data: &'data [u8],
    contents: FileContents<'data>,
    materialized: std::sync::OnceLock<Box<FileContents<'data>>>,
    deferred: bool,
    catalog_excluded: Vec<bool>,
}

#[derive(Debug)]
pub(crate) struct FileContents<'data> {
    pub sections: SectionTable<'data>,
    pub symbols: input::SymbolTable<'data>,
    pub directives: Vec<String>,
    pub import: Option<input::Import<'data>>,
    pub child_offsets: Vec<usize>,
    pub children: Vec<usize>,
}

impl<'data> std::ops::Deref for File<'data> {
    type Target = FileContents<'data>;
    fn deref(&self) -> &Self::Target {
        self.materialized.get().map_or(&self.contents, |v| &**v)
    }
}

#[derive(Debug)]
pub(crate) enum SectionTable<'data> {
    Owned(Vec<Section>),
    Borrowed(&'data [Section]),
}

impl From<Vec<Section>> for SectionTable<'_> {
    fn from(sections: Vec<Section>) -> Self {
        Self::Owned(sections)
    }
}

impl std::ops::Deref for SectionTable<'_> {
    type Target = [Section];
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(sections) => sections,
            Self::Borrowed(sections) => sections,
        }
    }
}

impl<'a> IntoIterator for &'a SectionTable<'_> {
    type Item = &'a Section;
    type IntoIter = std::slice::Iter<'a, Section>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl std::ops::DerefMut for File<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.materialized
            .get_mut()
            .map_or(&mut self.contents, |v| &mut **v)
    }
}

#[derive(Debug)]
pub(crate) struct Section {
    pub name: input::ByteRange,
    pub data: input::ByteRange,
    pub size: u32,
    pub alignment: u32,
    pub layout_alignment: std::sync::atomic::AtomicU32,
    pub layout_sort_rank: std::sync::atomic::AtomicU32,
    pub flags: u32,
    pub output_flags: std::sync::atomic::AtomicU32,
    pub selection: u8,
    pub parent: Option<u32>,
    pub representative: Option<u32>,
    pub key_hash: u64,
    pub anchor_symbol: Option<u32>,
    pub relocations: input::ByteRange,
    pub excluded: AtomicBool,
    pub retain: bool,
}

pub(crate) type Symbol = input::Symbol;

impl platform::Symbol for Symbol {
    fn as_common(&self) -> Option<platform::CommonSymbol> {
        (self.class == 2 && self.section == 0 && self.value != 0).then(|| platform::CommonSymbol {
            size: u64::from(self.value),
            part_id: OutputSectionId::from_u32(3)
                .part_id_with_alignment::<Coff>(Alignment { exponent: 3 }),
        })
    }
    fn is_undefined(&self) -> bool {
        !self.is_local() && self.weak.is_none() && self.section == 0 && self.value == 0
    }
    fn is_local(&self) -> bool {
        self.class != 2 && self.class != 105
    }
    fn is_absolute(&self) -> bool {
        self.section == -1
    }
    fn is_weak(&self) -> bool {
        self.weak.is_some()
    }
    fn visibility(&self) -> Visibility {
        Visibility::Default
    }
    fn value(&self) -> u64 {
        u64::from(self.value)
    }
    fn size(&self) -> u64 {
        u64::from(self.value)
    }
    fn has_name(&self) -> bool {
        !self.name.is_empty()
    }
    fn is_default_strippable(&self, _: &[u8]) -> bool {
        true
    }
    fn debug_string(&self) -> String {
        format!("COFF section {} value {}", self.section, self.value)
    }
    fn is_tls(&self) -> bool {
        false
    }
    fn is_interposable(&self) -> bool {
        false
    }
    fn is_func(&self) -> bool {
        false
    }
    fn is_ifunc(&self) -> bool {
        false
    }
    fn is_hidden(&self) -> bool {
        false
    }
    fn is_gnu_unique(&self) -> bool {
        false
    }
    fn with_hidden(self, _: bool) -> Self {
        self
    }
}

impl platform::SectionHeader for Section {
    fn is_alloc(&self) -> bool {
        !self.should_exclude()
    }
    fn is_writable(&self) -> bool {
        self.flags & 0x80000000 != 0
    }
    fn is_executable(&self) -> bool {
        self.flags & 0x20000000 != 0
    }
    fn is_tls(&self) -> bool {
        false
    }
    fn is_merge_section(&self) -> bool {
        false
    }
    fn is_strings(&self) -> bool {
        false
    }
    fn should_retain(&self) -> bool {
        self.retain
    }
    fn should_exclude(&self) -> bool {
        self.excluded.load(Ordering::Relaxed)
    }
    fn is_group(&self) -> bool {
        self.selection != 0
    }
    fn is_note(&self) -> bool {
        false
    }
    fn is_prog_bits(&self) -> bool {
        !self.is_no_bits()
    }
    fn is_no_bits(&self) -> bool {
        self.flags & 0x60 == 0
    }
    fn is_null(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Flags;
impl platform::SectionFlags for Flags {
    fn is_alloc(self) -> bool {
        true
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SectionType;
impl platform::SectionType for SectionType {
    fn is_rela(&self) -> bool {
        false
    }
    fn is_rel(&self) -> bool {
        false
    }
    fn is_symtab(&self) -> bool {
        false
    }
    fn is_strtab(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Attributes(pub u32);
impl platform::SectionAttributes for Attributes {
    type Platform = Coff;
    fn merge(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
    fn apply(&self, sections: &mut OutputSections<Coff>, id: OutputSectionId) {
        sections
            .section_infos
            .get_mut(id)
            .section_attributes
            .merge(*self);
    }
    fn is_null(&self) -> bool {
        self.0 == 0
    }
    fn is_alloc(&self) -> bool {
        true
    }
    fn is_executable(&self) -> bool {
        self.0 & 0x20000000 != 0
    }
    fn is_tls(&self) -> bool {
        false
    }
    fn occupies_only_tls_address_space(&self) -> bool {
        false
    }
    fn is_writable(&self) -> bool {
        self.0 & 0x80000000 != 0
    }
    fn is_no_bits(&self) -> bool {
        self.0 & 0x60 == 0
    }
    fn flags(&self) -> Flags {
        Flags
    }
    fn ty(&self) -> SectionType {
        SectionType
    }
    fn set_to_default_type(&mut self) {
        self.0 |= 0x40000040;
    }
}

impl<'data> File<'data> {
    fn parse_coff(data: &'data [u8], name: String) -> Result<Self> {
        let contents = match input::parse(data, name)? {
            input::Parsed::Object(object) => Self::object_contents(object),
            input::Parsed::Metadata => FileContents {
                sections: Vec::new().into(),
                symbols: Default::default(),
                directives: Vec::new(),
                import: None,
                child_offsets: Vec::new(),
                children: Vec::new(),
            },
            input::Parsed::Import(import) => FileContents {
                sections: Vec::new().into(),
                symbols: Default::default(),
                directives: Vec::new(),
                import: Some(import),
                child_offsets: Vec::new(),
                children: Vec::new(),
            },
        };
        Ok(Self {
            data,
            contents,
            materialized: Default::default(),
            deferred: false,
            catalog_excluded: Vec::new(),
        })
    }

    fn object_contents(object: input::Object) -> FileContents<'data> {
        FileContents {
            sections: object
                .sections
                .into_iter()
                .map(|s| Section {
                    name: s.name,
                    data: s.data,
                    size: s.size,
                    alignment: s.align,
                    layout_alignment: std::sync::atomic::AtomicU32::new(s.align),
                    layout_sort_rank: std::sync::atomic::AtomicU32::new(0),
                    flags: s.flags,
                    output_flags: std::sync::atomic::AtomicU32::new(s.flags),
                    selection: s.selection,
                    parent: s.parent,
                    representative: s.key_symbol,
                    key_hash: s
                        .key_symbol
                        .map_or(0, |index| object.symbols[index as usize].name_hash),
                    anchor_symbol: s.anchor_symbol,
                    relocations: s.relocs,
                    excluded: AtomicBool::new(s.excluded),
                    retain: s.selection == 0 || s.tls || s.crt,
                })
                .collect::<Vec<_>>()
                .into(),
            symbols: object.symbols,
            directives: object.directives,
            import: None,
            child_offsets: object.child_offsets,
            children: object.children,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Relocation {
    pub offset: u32,
    pub symbol: u32,
    pub kind: u16,
}

#[derive(Clone, Copy)]
pub(crate) struct Relocations<'data>(pub &'data [u8]);
impl<'data> platform::RelocationList<'data> for Relocations<'data> {
    fn num_relocations(&self) -> usize {
        self.0.len() / 10
    }
}
impl<'data> platform::RelocationSequence<'data> for Relocations<'data> {
    type Rel = Relocation;
    fn rel_iter(&self) -> impl Iterator<Item = Relocation> {
        self.0.chunks_exact(10).map(|bytes| {
            let r = input::Reloc::read(bytes);
            Relocation {
                offset: r.offset,
                symbol: r.symbol as u32,
                kind: r.kind,
            }
        })
    }
    fn subsequence(&self, range: std::ops::Range<usize>) -> Self {
        Self(&self.0[range.start * 10..range.end * 10])
    }
    fn num_relocations(&self) -> usize {
        self.0.len() / 10
    }
}
impl platform::Relocation for Relocation {
    type Sequence<'data> = Relocations<'data>;
    type Platform = Coff;
    fn symbol(&self) -> Option<object::SymbolIndex> {
        (self.kind != 0).then_some(object::SymbolIndex(self.symbol as usize))
    }
    fn raw_type(&self) -> u16 {
        self.kind
    }
    fn offset(&self) -> u64 {
        u64::from(self.offset)
    }
    fn addend(&self) -> i64 {
        0
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Name<'data>(pub &'data [u8], pub Option<u64>);
impl std::fmt::Display for Name<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.0))
    }
}
impl<'data> platform::RawSymbolName<'data> for Name<'data> {
    fn parse(bytes: &'data [u8]) -> Self {
        Self(bytes, None)
    }
    fn name(&self) -> &'data [u8] {
        self.0
    }
    fn name_hash(&self) -> u64 {
        self.1.unwrap_or_else(|| crate::hash::hash_bytes(self.0))
    }
    fn with_name_hash(mut self, hash: Option<u64>) -> Self {
        self.1 = hash;
        self
    }
    fn version_name(&self) -> Option<&'data [u8]> {
        None
    }
    fn is_default(&self) -> bool {
        true
    }
}
pub(crate) struct Versions;
impl<'data> platform::VerneedTable<'data> for Versions {
    fn version_name(&self, _: object::SymbolIndex) -> Option<&'data [u8]> {
        None
    }
}
#[derive(Debug)]
pub(crate) struct DynamicTags;
impl<'data> platform::DynamicTagValues<'data> for DynamicTags {
    fn lib_name(&self, _: &crate::input_data::InputRef<'data>) -> &'data [u8] {
        b""
    }
}
pub(crate) struct Indexes;
impl platform::NonAddressableIndexes for Indexes {
    fn new<P: platform::Platform>(_: &crate::symbol_db::SymbolDb<P>) -> Self {
        Self
    }
}
pub(crate) struct BuiltIn;
impl platform::BuiltInSectionDetails for BuiltIn {}

fn imports_object(imports: &mut Vec<input::Import<'_>>) -> Result<Vec<u8>> {
    use object::write::{Object, Relocation, Symbol, SymbolSection};
    use object::{
        Architecture, BinaryFormat, Endianness, RelocationFlags, SectionKind, SymbolFlags,
        SymbolKind, SymbolScope,
    };
    imports.sort_by(|a, b| {
        a.dll
            .to_ascii_lowercase()
            .cmp(&b.dll.to_ascii_lowercase())
            .then(a.symbol.cmp(&b.symbol))
    });
    imports.dedup_by(|a, b| a.dll.eq_ignore_ascii_case(&b.dll) && a.symbol == b.symbol);
    let mut object = Object::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
    let descriptors = object.add_section(Vec::new(), b".idata$2".to_vec(), SectionKind::Data);
    let ilt = object.add_section(Vec::new(), b".idata$4".to_vec(), SectionKind::Data);
    let iat = object.add_section(Vec::new(), b".idata$5".to_vec(), SectionKind::Data);
    let names = object.add_section(Vec::new(), b".idata$6".to_vec(), SectionKind::ReadOnlyData);
    let text = object.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    let ilt_symbol = object.section_symbol(ilt);
    let iat_symbol = object.section_symbol(iat);
    let names_symbol = object.section_symbol(names);
    let add_rva = |object: &mut Object, section, offset, symbol, addend| -> Result {
        object.add_relocation(
            section,
            Relocation {
                offset,
                symbol,
                addend,
                flags: RelocationFlags::Coff {
                    typ: pe::IMAGE_REL_AMD64_ADDR32NB,
                },
            },
        )?;
        Ok(())
    };
    let mut cursor = 0;
    while cursor < imports.len() {
        let first = cursor;
        while cursor < imports.len()
            && imports[first]
                .dll
                .eq_ignore_ascii_case(&imports[cursor].dll)
        {
            cursor += 1;
        }
        let descriptor = object.append_section_data(descriptors, &[0; 20], 4);
        let dll_offset =
            object.append_section_data(names, &[imports[first].dll.as_bytes(), b"\0"].concat(), 1);
        let ilt_offset = object.section(ilt).data().len() as u64;
        let iat_offset = object.section(iat).data().len() as u64;
        add_rva(
            &mut object,
            descriptors,
            descriptor,
            ilt_symbol,
            ilt_offset as i64,
        )?;
        add_rva(
            &mut object,
            descriptors,
            descriptor + 12,
            names_symbol,
            dll_offset as i64,
        )?;
        add_rva(
            &mut object,
            descriptors,
            descriptor + 16,
            iat_symbol,
            iat_offset as i64,
        )?;
        for import in &imports[first..cursor] {
            let thunk = if import.name.is_some() {
                [0; 8]
            } else {
                ((1u64 << 63) | u64::from(import.ordinal)).to_le_bytes()
            };
            let lookup = object.append_section_data(ilt, &thunk, 8);
            let address = object.append_section_data(iat, &thunk, 8);
            if let Some(name) = &import.name {
                let hint = object.append_section_data(
                    names,
                    &[&[0, 0], name.as_bytes(), b"\0"].concat(),
                    2,
                );
                add_rva(&mut object, ilt, lookup, names_symbol, hint as i64)?;
                add_rva(&mut object, iat, address, names_symbol, hint as i64)?;
            }
            let pointer = object.add_symbol(Symbol {
                name: format!("__imp_{}", import.symbol).into_bytes(),
                value: address,
                size: 8,
                kind: SymbolKind::Data,
                scope: SymbolScope::Linkage,
                weak: false,
                section: SymbolSection::Section(iat),
                flags: SymbolFlags::None,
            });
            let (section, value, kind) = if import.code {
                let start = object.append_section_data(text, &[0xff, 0x25, 0, 0, 0, 0], 2);
                object.add_relocation(
                    text,
                    Relocation {
                        offset: start + 2,
                        symbol: pointer,
                        addend: -4,
                        flags: RelocationFlags::Coff {
                            typ: pe::IMAGE_REL_AMD64_REL32,
                        },
                    },
                )?;
                (text, start, SymbolKind::Text)
            } else {
                (iat, address, SymbolKind::Data)
            };
            object.add_symbol(Symbol {
                name: import.symbol.as_bytes().to_vec(),
                value,
                size: 0,
                kind,
                scope: SymbolScope::Linkage,
                weak: false,
                section: SymbolSection::Section(section),
                flags: SymbolFlags::None,
            });
        }
        object.append_section_data(ilt, &[0; 8], 8);
        object.append_section_data(iat, &[0; 8], 8);
    }
    object.append_section_data(descriptors, &[0; 20], 4);
    Ok(object.write()?)
}

impl<'data> platform::ObjectFile<'data> for File<'data> {
    type Platform = Coff;
    fn parse_bytes(data: &'data [u8], _: bool) -> Result<Self> {
        Self::parse_coff(data, "<COFF object>".into())
    }
    fn parse(input: &crate::input_data::InputBytes<'data>, _: &CoffArgs) -> Result<Self> {
        if input.input.has_archive_semantics() && !input.modifiers.whole_archive {
            if let Some(object) = input::catalog(input.data, "<COFF archive member>")? {
                return Ok(Self {
                    data: input.data,
                    contents: FileContents {
                        sections: Vec::new().into(),
                        symbols: object.symbols,
                        directives: Vec::new(),
                        import: None,
                        child_offsets: Vec::new(),
                        children: Vec::new(),
                    },
                    materialized: Default::default(),
                    deferred: true,
                    catalog_excluded: object.excluded,
                });
            }
        }
        // The shared parser adds the input path only when reporting an error.
        Self::parse_coff(input.data, "<COFF object>".into())
    }
    fn materialize(&self) -> Result<bool> {
        if !self.deferred || self.materialized.get().is_some() {
            return Ok(false);
        }
        let parsed = Self::parse_coff(self.data, "<selected COFF member>".into())?;
        crate::ensure!(
            parsed.num_symbols() == self.num_symbols()
                && parsed.num_sections() == self.num_sections(),
            "COFF catalog changed during materialization"
        );
        Ok(self.materialized.set(Box::new(parsed.contents)).is_ok())
    }
    fn is_dynamic(&self) -> bool {
        false
    }
    fn permits_optional_input_coalescing(&self) -> bool {
        self.import.is_some()
    }
    fn num_symbols(&self) -> usize {
        self.symbols.len()
    }
    fn symbols_iter(&self) -> impl Iterator<Item = &Symbol> {
        self.symbols.iter()
    }
    fn symbol(&self, index: object::SymbolIndex) -> Result<&Symbol> {
        self.symbols
            .get(index.0)
            .context("Invalid COFF symbol index")
    }
    fn section_size(&self, section: &Section) -> Result<u64> {
        Ok(u64::from(section.size))
    }
    fn symbol_name(&self, symbol: &Symbol) -> Result<&'data [u8]> {
        Ok(&self.data[symbol.name.range()])
    }
    fn symbol_name_hash(&self, symbol: &Symbol) -> Option<u64> {
        (!symbol.is_local()).then_some(symbol.name_hash)
    }
    fn symbol_offset_in_section(&self, symbol: &Symbol, _: object::SectionIndex) -> Result<u64> {
        Ok(u64::from(symbol.value))
    }
    fn num_sections(&self) -> usize {
        if self.deferred && self.materialized.get().is_none() {
            self.catalog_excluded.len()
        } else {
            self.sections.len()
        }
    }
    fn section_iter(&self) -> std::slice::Iter<'_, Section> {
        self.sections.iter()
    }
    fn enumerate_sections(&self) -> impl Iterator<Item = (object::SectionIndex, &Section)> {
        self.sections
            .iter()
            .enumerate()
            .map(|(i, s)| (object::SectionIndex(i), s))
    }
    fn section(&self, index: object::SectionIndex) -> Result<&Section> {
        self.sections
            .get(index.0)
            .context("Invalid COFF section index")
    }
    fn section_by_name(&self, name: &str) -> Option<(object::SectionIndex, &Section)> {
        self.enumerate_sections()
            .find(|(_, s)| &self.data[s.name.range()] == name.as_bytes())
    }
    fn symbol_section(
        &self,
        symbol: &Symbol,
        _: object::SymbolIndex,
    ) -> Result<Option<object::SectionIndex>> {
        Ok((symbol.section > 0).then(|| object::SectionIndex(symbol.section as usize - 1)))
    }
    fn symbol_versions(&self) -> &[()] {
        &[]
    }
    fn finalise_sizes_dynamic(
        &self,
        _: &[u8],
        _: &mut (),
        _: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> Result {
        Ok(())
    }
    fn apply_non_addressable_indexes_dynamic(
        &self,
        _: &mut Indexes,
        _: &mut (),
        _: &mut (),
    ) -> Result {
        Ok(())
    }
    fn section_name(&self, index: object::SectionIndex) -> Result<&'data [u8]> {
        Ok(&self.data[self.section(index)?.name.range()])
    }
    fn raw_section_data(&self, section: &Section) -> Result<&'data [u8]> {
        Ok(&self.data[section.data.range()])
    }
    fn section_data(
        &self,
        section: &Section,
        _: &bumpalo_herd::Member<'data>,
        _: &crate::resolution::LoadedMetrics,
    ) -> Result<&'data [u8]> {
        self.raw_section_data(section)
    }
    fn copy_section_data(&self, section: &Section, out: &mut [u8]) -> Result {
        let data = self.raw_section_data(section)?;
        crate::ensure!(
            data.len() <= out.len(),
            "COFF section data exceeds output allocation"
        );
        out[..data.len()].copy_from_slice(data);
        out[data.len()..].fill(0);
        Ok(())
    }
    fn section_data_cow(&self, section: &Section) -> Result<Cow<'data, [u8]>> {
        Ok(Cow::Borrowed(self.raw_section_data(section)?))
    }
    fn section_alignment(&self, section: &Section) -> Result<u64> {
        Ok(u64::from(
            section.layout_alignment.load(Ordering::Relaxed).max(1),
        ))
    }
    fn relocations(&self, index: object::SectionIndex, _: &()) -> Result<Relocations<'data>> {
        Ok(Relocations(
            &self.data[self.section(index)?.relocations.range()],
        ))
    }
    fn parse_relocations(&self) -> Result<()> {
        Ok(())
    }
    fn symbol_version_debug(&self, _: object::SymbolIndex) -> Option<String> {
        None
    }
    fn section_display_name(&self, index: object::SectionIndex) -> Cow<'data, str> {
        String::from_utf8_lossy(self.section_name(index).unwrap_or_default())
    }
    fn dynamic_tag_values(&self) -> Option<DynamicTags> {
        None
    }
    fn get_version_names(&self) -> Result<()> {
        Ok(())
    }
    fn get_symbol_name_and_version(
        &self,
        symbol: &Symbol,
        _: usize,
        _: &(),
    ) -> Result<Name<'data>> {
        Ok(Name(
            self.symbol_name(symbol)?,
            self.symbol_name_hash(symbol),
        ))
    }
    fn should_enforce_undefined(&self, _: &layout::GraphResources<'data, '_, Coff>) -> bool {
        false
    }
    fn verneed_table(&self) -> Result<Versions> {
        Ok(Versions)
    }
    fn process_gnu_note_section(&self, _: &mut (), _: object::SectionIndex) -> Result {
        Ok(())
    }
    fn dynamic_tags(&self) -> Result<&'data [()]> {
        Ok(&[])
    }
}
