use super::input::Import;
use super::input::NameId;
use super::input::Object;
use super::input::Parsed;
use super::input::Reloc;
use super::input::ResolvedTarget;
use super::input::{self};
use crate::args::InputSpec;
use crate::args::coff::CoffArgs;
use crate::bail;
use crate::ensure;
use crate::error::Context as _;
use crate::error::Result;
use crate::fs::FileSystem;
use crate::fs::InputFileData as _;
use hashbrown::HashMap;
use hashbrown::HashSet;
use rayon::prelude::*;
use smallvec::SmallVec;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::hash::BuildHasher as _;
use std::ops::Range;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Instant;

#[derive(Default)]
struct WorkTiming {
    parse: AtomicU64,
    index_scan: AtomicU64,
    intern: AtomicU64,
    selection: AtomicU64,
}

struct WorkTimer<'a> {
    start: Option<Instant>,
    total: &'a AtomicU64,
}

impl Drop for WorkTimer<'_> {
    fn drop(&mut self) {
        if let Some(start) = self.start {
            self.total
                .fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }
    }
}

fn work_timer(total: &AtomicU64, enabled: bool) -> WorkTimer<'_> {
    WorkTimer {
        start: enabled.then(Instant::now),
        total,
    }
}

#[derive(Default)]
struct Names {
    ids: HashMap<u64, NameId>,
    values: Vec<(Range<usize>, Option<NameId>)>,
    bytes: Vec<u8>,
    hasher: hashbrown::DefaultHashBuilder,
}

impl Names {
    fn intern(&mut self, name: &str) -> NameId {
        self.intern_hashed(name, self.hasher.hash_one(name))
    }
    fn find(&self, name: &str) -> Option<NameId> {
        self.find_hashed(name, self.hasher.hash_one(name))
    }
    fn find_hashed(&self, name: &str, hash: u64) -> Option<NameId> {
        let mut next = self.ids.get(&hash).copied();
        while let Some(id) = next {
            if self.get(id) == name {
                return Some(id);
            }
            next = self.values[id as usize].1;
        }
        None
    }
    fn intern_hashed(&mut self, name: &str, hash: u64) -> NameId {
        if let Some(id) = self.find_hashed(name, hash) {
            return id;
        }
        let id = NameId::try_from(self.values.len()).expect("Too many COFF symbol names");
        let start = self.bytes.len();
        self.bytes.extend_from_slice(name.as_bytes());
        self.values
            .push((start..self.bytes.len(), self.ids.insert(hash, id)));
        id
    }
    fn get(&self, id: NameId) -> &str {
        // SAFETY: Only valid str bytes are appended; existing bytes and ranges never change.
        unsafe { std::str::from_utf8_unchecked(&self.bytes[self.values[id as usize].0.clone()]) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Target {
    Symbol(usize, usize),
    Import(usize, bool),
    ImageBase,
    Archive(usize),
}

pub(super) struct Resolver<'a, F: FileSystem> {
    pub fs: &'a F,
    pub args: &'a CoffArgs,
    pub objects: Vec<Object>,
    pub imports: Vec<Import>,
    definitions: Vec<Option<ResolvedTarget>>,
    pub commons: BTreeMap<String, (u32, u32)>,
    pub entry: String,
    candidates: Vec<SmallVec<[ResolvedTarget; 1]>>,
    active_names: Vec<bool>,
    selected: Vec<Option<(u32, u32)>>,
    aliases: HashMap<NameId, NameId>,
    mismatches: HashMap<String, String>,
    forced: HashSet<NameId>,
    loaded: HashSet<PathBuf>,
    library_cache: HashMap<String, PathBuf>,
    pending: VecDeque<String>,
    search: Vec<PathBuf>,
    pub merges: HashMap<String, String>,
    pub section_flags: HashMap<String, String>,
    excluded_libraries: HashSet<String>,
    no_default_libraries: bool,
    archive_members: HashMap<PathBuf, Vec<usize>>,
    whole_archive: bool,
    newly_active: VecDeque<usize>,
    names: Names,
    inputs: Vec<F::Input>,
    fallback_members: Vec<usize>,
    next_order: usize,
    prepared: HashMap<usize, Result<Object>>,
    work_timing: WorkTiming,
}

impl<'a, F: FileSystem> Resolver<'a, F> {
    pub fn new(fs: &'a F, args: &'a CoffArgs) -> Self {
        let mut search: Vec<_> = args
            .lib_search_path
            .iter()
            .map(|p| p.to_path_buf())
            .collect();
        if let Some(paths) = std::env::var_os("LIB") {
            search.extend(std::env::split_paths(&paths));
        }
        Self {
            fs,
            args,
            objects: Vec::new(),
            imports: Vec::new(),
            candidates: Vec::new(),
            active_names: Vec::new(),
            definitions: Vec::new(),
            commons: BTreeMap::new(),
            entry: String::new(),
            selected: Vec::new(),
            aliases: HashMap::new(),
            mismatches: HashMap::new(),
            forced: HashSet::new(),
            loaded: HashSet::new(),
            library_cache: HashMap::new(),
            pending: VecDeque::new(),
            search,
            merges: HashMap::from_iter([(".CRT".into(), ".rdata".into())]),
            section_flags: HashMap::new(),
            excluded_libraries: args
                .excluded_default_libraries
                .iter()
                .map(|s| library_name(s))
                .collect(),
            no_default_libraries: args.no_default_libraries,
            archive_members: HashMap::new(),
            whole_archive: false,
            newly_active: VecDeque::new(),
            names: Names::default(),
            inputs: Vec::new(),
            fallback_members: Vec::new(),
            next_order: 0,
            prepared: HashMap::new(),
            work_timing: WorkTiming::default(),
        }
    }

    pub fn load(&mut self) -> Result {
        for input in &self.args.common.inputs {
            let path = match &input.spec {
                InputSpec::File(p) => self.find_file(p)?,
                InputSpec::Search(p) | InputSpec::Lib(p) => self.find_library(p)?,
            };
            self.load_file(&path, input.modifiers.whole_archive)?;
        }
        for d in &self.args.directives {
            self.directive(d)?;
        }
        for lib in &self.args.default_libraries {
            self.pending.push_back(lib.clone());
        }
        self.load_pending()?;
        self.entry = self.args.entry.clone().unwrap_or_else(|| {
            if self
                .names
                .find("wmain")
                .is_some_and(|id| self.candidates(id).is_some())
            {
                "wmainCRTStartup".into()
            } else if self
                .names
                .find("WinMain")
                .is_some_and(|id| self.candidates(id).is_some())
            {
                "WinMainCRTStartup".into()
            } else {
                "mainCRTStartup".into()
            }
        });
        Ok(())
    }

    fn find_file(&self, path: &Path) -> Result<PathBuf> {
        if self.fs.file_type(path).is_ok() {
            return Ok(path.to_owned());
        }
        for dir in &self.search {
            let candidate = dir.join(path);
            if self.fs.file_type(&candidate).is_ok() {
                return Ok(candidate);
            }
        }
        bail!("COFF input not found: {}", path.display())
    }

    fn find_library(&mut self, name: &str) -> Result<PathBuf> {
        if let Some(path) = self.library_cache.get(name) {
            return Ok(path.clone());
        }
        let mut path = PathBuf::from(name);
        if path.extension().is_none() {
            path.set_extension("lib");
        }
        let path = self.find_file(&path)?;
        self.library_cache.insert(name.to_owned(), path.clone());
        Ok(path)
    }

    fn load_pending(&mut self) -> Result<bool> {
        let mut changed = false;
        while let Some(name) = self.pending.pop_front() {
            if self.no_default_libraries || self.excluded_libraries.contains(&library_name(&name)) {
                continue;
            }
            let path = self.find_library(&name)?;
            changed |= self.load_file(&path, false)?;
        }
        Ok(changed)
    }

    fn load_file(&mut self, path: &Path, whole: bool) -> Result<bool> {
        let path = self.fs.absolute_path(path)?;
        if !self.loaded.insert(path.clone()) {
            if whole {
                for o in self.archive_members.get(&path).cloned().unwrap_or_default() {
                    self.activate(o)?;
                }
            }
            return Ok(false);
        }
        let (bytes, _) = self
            .fs
            .open_input(&path, self.args.common.prepopulate_maps)?;
        let input = self.inputs.len();
        self.inputs.push(bytes);
        let data = self.inputs[input].bytes();
        if data.starts_with(b"!<arch>\n") {
            struct Member {
                name: String,
                range: Range<usize>,
                parsed: Option<Parsed>,
                names: Vec<NameId>,
            }
            let archive = object::read::archive::ArchiveFile::parse(data)?;
            ensure!(!archive.is_thin(), "Thin COFF archives are unsupported");
            let indexed = archive.symbols()?.is_some();
            let mut members = Vec::new();
            let mut offsets = HashMap::new();
            for member in archive.members() {
                let member = member?;
                let member_name = std::str::from_utf8(member.name())?;
                let entry = member.data(data)?;
                if member_name.ends_with(".rmeta") || entry.starts_with(b"rust") {
                    continue;
                }
                let (start, size) = member.file_range();
                let kind = input::kind(entry)?;
                let parsed = if kind == object::FileKind::CoffImport {
                    Some(input::parse(entry, member_name.to_owned())?)
                } else {
                    ensure!(
                        matches!(kind, object::FileKind::Coff | object::FileKind::CoffBig),
                        "Unsupported COFF archive member {member_name}"
                    );
                    None
                };
                offsets.insert(start, members.len());
                members.push(Member {
                    name: format!("{}({member_name})", path.display()),
                    range: start as usize..(start + size) as usize,
                    parsed,
                    names: Vec::new(),
                });
            }
            let scan = |member: &Member| -> Result<Vec<&str>> {
                let _timer = work_timer(
                    &self.work_timing.index_scan,
                    self.args.common.time_phase_options.is_some(),
                );
                if member.parsed.is_some() {
                    Ok(Vec::new())
                } else {
                    input::archive_names(&data[member.range.clone()], indexed)
                }
            };
            let scanned: Vec<_> = if members.len() >= 2
                && data.len() >= 1024 * 1024
                && rayon::current_num_threads() > 1
                && !self.args.common.num_threads.is_some_and(|n| n.get() == 1)
            {
                members.par_iter().map(scan).collect()
            } else {
                members.iter().map(scan).collect()
            };
            for (member, names) in members.iter_mut().zip(scanned) {
                member.names = names?
                    .into_iter()
                    .map(|name| self.names.intern(name))
                    .collect();
            }
            if let Some(symbols) = archive.symbols()? {
                let mut indexed_offsets = HashMap::new();
                for symbol in symbols {
                    let symbol = symbol?;
                    let offset = symbol.offset();
                    let index = if let Some(index) = indexed_offsets.get(&offset.0) {
                        *index
                    } else {
                        let member = archive.member(offset)?;
                        let index = offsets.get(&member.file_range().0).copied();
                        indexed_offsets.insert(offset.0, index);
                        index
                    };
                    if let Some(i) = index {
                        if members[i].parsed.is_none() {
                            members[i]
                                .names
                                .push(self.names.intern(std::str::from_utf8(symbol.name())?));
                        }
                    }
                }
            }
            let first_object = self.objects.len();
            for member in members {
                let order = self.next_order;
                self.next_order += 1;
                if let Some(parsed) = member.parsed {
                    self.add(parsed, member.name, false, input, member.range, order)?;
                } else {
                    let o = self.objects.len();
                    ensure!(o < 1 << 30, "Too many COFF objects");
                    self.objects.push(Object {
                        name: member.name,
                        input,
                        range: member.range,
                        order,
                        ..Object::default()
                    });
                    let mut names = member.names;
                    names.sort_unstable();
                    names.dedup();
                    for name in names {
                        self.add_candidate(name, Target::Archive(o));
                    }
                    if indexed {
                        self.fallback_members.push(o);
                    }
                    if whole || self.whole_archive {
                        self.activate(o)?;
                    }
                }
            }
            self.archive_members
                .insert(path, (first_object..self.objects.len()).collect());
        } else {
            let range = 0..data.len();
            let parsed = {
                let _timer = work_timer(
                    &self.work_timing.parse,
                    self.args.common.time_phase_options.is_some(),
                );
                input::parse(data, path.to_string_lossy().into_owned())?
            };
            let order = self.next_order;
            self.next_order += 1;
            self.add(
                parsed,
                path.to_string_lossy().into_owned(),
                true,
                input,
                range,
                order,
            )?;
        }
        Ok(true)
    }

    fn add(
        &mut self,
        parsed: Parsed,
        name: String,
        active: bool,
        input: usize,
        range: Range<usize>,
        order: usize,
    ) -> Result {
        match parsed {
            Parsed::Metadata => {}
            Parsed::Import(mut import) => {
                import.order = order;
                let i = self.imports.len();
                let iat = self.names.intern(&format!("__imp_{}", import.symbol));
                self.add_candidate(iat, Target::Import(i, true));
                if import.code {
                    let name = self.names.intern(&import.symbol);
                    self.add_candidate(name, Target::Import(i, false));
                }
                self.imports.push(import);
            }
            Parsed::Object(mut object) => {
                object.name = name;
                object.input = input;
                object.range = range;
                object.order = order;
                let i = self.objects.len();
                ensure!(i < 1 << 30, "Too many COFF objects");
                self.intern_symbols(&mut object);
                for (s, symbol) in object.symbols.iter().enumerate() {
                    if symbol.definition() || symbol.weak.is_some() {
                        self.add_candidate(symbol.name_id, Target::Symbol(i, s));
                    }
                }
                self.objects.push(object);
                if active {
                    self.activate(i)?;
                }
            }
        }
        Ok(())
    }

    fn activate(&mut self, object: usize) -> Result<bool> {
        if self.objects[object].active {
            return Ok(false);
        }
        if !self.objects[object].parsed {
            let slot = &self.objects[object];
            let mut parsed = if let Some(prepared) = self.prepared.remove(&object) {
                prepared?
            } else {
                self.parse_member(object)?
            };
            parsed.input = slot.input;
            parsed.range = slot.range.clone();
            parsed.order = slot.order;
            self.intern_symbols(&mut parsed);
            // Candidates are already indexed. Definitions are rebuilt from the parsed symbols.
            self.objects[object] = parsed;
        }
        self.objects[object].active = true;
        self.active_names.resize(self.names.values.len(), false);
        self.selected.resize(self.names.values.len(), None);
        for symbol in &self.objects[object].symbols {
            if symbol.definition() || symbol.weak.is_some() {
                self.active_names[symbol.name_id as usize] = true;
            }
        }
        self.newly_active.push_back(object);
        let selection_start = self
            .args
            .common
            .time_phase_options
            .is_some()
            .then(Instant::now);
        for i in 0..self.objects[object].sections.len() {
            let section = &self.objects[object].sections[i];
            if section.selection == 0 || section.selection == 5 {
                continue;
            }
            let key = section.key;
            if let Some((old_obj, old_sec)) = self.selected[key as usize] {
                let old_obj = old_obj as usize;
                let old_sec = old_sec as usize;
                let old = &self.objects[old_obj].sections[old_sec];
                let replace = match section.selection {
                    1 => bail!(
                        "Duplicate NODUPLICATES COMDAT {}: {} section {} and {} section {}",
                        self.names.get(key),
                        self.objects[old_obj].name,
                        old_sec + 1,
                        self.objects[object].name,
                        i + 1
                    ),
                    2 => false,
                    3 => {
                        ensure!(
                            old.size == section.size,
                            "COMDAT size mismatch: {}",
                            self.names.get(key)
                        );
                        false
                    }
                    4 => {
                        let same_relocs = old.relocs.len() == section.relocs.len()
                            && (0..old.relocs.len() / 10).all(|index| {
                                let a = self.reloc(old_obj, old_sec, index);
                                let b = self.reloc(object, i, index);
                                a.offset == b.offset
                                    && a.kind == b.kind
                                    && self.symbol_name(old_obj, a.symbol)
                                        == self.symbol_name(object, b.symbol)
                            });
                        ensure!(
                            self.section_data(old_obj, old_sec) == self.section_data(object, i)
                                && old.size == section.size
                                && same_relocs,
                            "COMDAT content mismatch: {}",
                            self.names.get(key)
                        );
                        false
                    }
                    6 => section.size > old.size,
                    7 => true,
                    n => bail!(
                        "Unsupported COMDAT selection {n} for {}",
                        self.names.get(key)
                    ),
                };
                if replace {
                    self.objects[old_obj].sections[old_sec].replacement =
                        Some((object.try_into().unwrap(), i.try_into().unwrap()));
                    self.selected[key as usize] = Some((object as u32, i as u32));
                } else {
                    self.objects[object].sections[i].replacement =
                        Some((old_obj.try_into().unwrap(), old_sec.try_into().unwrap()));
                }
            } else {
                self.selected[key as usize] = Some((object as u32, i as u32));
            }
        }
        if let Some(start) = selection_start {
            self.work_timing
                .selection
                .fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }
        for d in self.objects[object].directives.clone() {
            self.directive(&d)?;
        }
        Ok(true)
    }

    fn intern_symbols(&mut self, object: &mut Object) {
        let _timer = work_timer(
            &self.work_timing.intern,
            self.args.common.time_phase_options.is_some(),
        );
        let data = &self.inputs[object.input].bytes()[object.range.clone()];
        let mut fallbacks = Vec::new();
        for symbol in &mut object.symbols {
            if symbol.external() {
                symbol.name_id = self
                    .names
                    .intern(std::str::from_utf8(&data[symbol.name.range()]).unwrap());
            }
            if let Some((fallback, _)) = symbol.weak() {
                fallbacks.push(fallback);
            }
        }
        for index in fallbacks {
            let symbol = &mut object.symbols[index];
            symbol.name_id = self
                .names
                .intern(std::str::from_utf8(&data[symbol.name.range()]).unwrap());
        }
        let mut local_key = String::new();
        for (s, section) in object.sections.iter_mut().enumerate() {
            if section.selection != 0 && section.selection != 5 {
                section.key = if let Some(symbol) = section.key_symbol {
                    object.symbols[symbol as usize].name_id
                } else {
                    local_key.clear();
                    write!(local_key, "{}#{s}", object.name).unwrap();
                    self.names.intern(&local_key)
                };
            }
        }
    }

    pub fn object_data(&self, object: usize) -> &[u8] {
        let object = &self.objects[object];
        &self.inputs[object.input].bytes()[object.range.clone()]
    }

    pub fn section_data(&self, object: usize, section: usize) -> &[u8] {
        &self.object_data(object)[self.objects[object].sections[section].data.range()]
    }

    pub fn section_name(&self, object: usize, section: usize) -> &str {
        std::str::from_utf8(self.section_name_bytes(object, section)).unwrap()
    }

    pub fn section_name_bytes(&self, object: usize, section: usize) -> &[u8] {
        &self.object_data(object)[self.objects[object].sections[section].name.range()]
    }

    fn parse_member(&self, object: usize) -> Result<Object> {
        crate::verbose_timing_phase!("Parse COFF member");
        let _timer = work_timer(
            &self.work_timing.parse,
            self.args.common.time_phase_options.is_some(),
        );
        match input::parse(self.object_data(object), self.objects[object].name.clone())? {
            Parsed::Object(object) => Ok(object),
            _ => bail!("Expected COFF object {}", self.objects[object].name),
        }
    }

    fn active_name(&self, name: NameId) -> bool {
        self.active_names
            .get(name as usize)
            .copied()
            .unwrap_or(false)
    }

    fn candidates(&self, name: NameId) -> Option<&[ResolvedTarget]> {
        self.candidates
            .get(name as usize)
            .filter(|c| !c.is_empty())
            .map(|c| c.as_slice())
    }

    fn add_candidate(&mut self, name: NameId, target: Target) {
        if self.candidates.len() <= name as usize {
            self.candidates
                .resize_with(name as usize + 1, SmallVec::new);
        }
        self.candidates[name as usize].push(ResolvedTarget::compress(target));
    }

    fn prepare_members(&mut self, needs: &[NameId]) {
        let mut predicted = HashSet::new();
        let mut members: Vec<_> = needs
            .iter()
            .filter_map(|name| {
                if self.active_name(*name) {
                    return None;
                }
                let candidates = self.candidates(*name)?;
                if candidates.iter().any(|target| match target.expand() {
                    Target::Archive(o) | Target::Symbol(o, _) => {
                        self.objects[o].active || predicted.contains(&o)
                    }
                    Target::Import(i, _) => self.imports[i].live,
                    Target::ImageBase => true,
                }) {
                    return None;
                }
                match candidates.first()?.expand() {
                    Target::Archive(o) => {
                        predicted.insert(o);
                        (!self.objects[o].parsed && !self.prepared.contains_key(&o)).then_some(o)
                    }
                    _ => None,
                }
            })
            .collect();
        members.sort_unstable();
        members.dedup();
        let bytes: usize = members.iter().map(|o| self.objects[*o].range.len()).sum();
        if members.len() < 2
            || bytes < 1024 * 1024
            || rayon::current_num_threads() < 2
            || self.args.common.num_threads.is_some_and(|n| n.get() == 1)
        {
            return;
        }
        let results: Vec<_> = members
            .par_iter()
            .map(|o| (*o, self.parse_member(*o)))
            .collect();
        self.prepared.extend(results);
    }

    pub fn symbol_name(&self, object: usize, symbol: usize) -> &str {
        std::str::from_utf8(
            &self.object_data(object)[self.objects[object].symbols[symbol].name.range()],
        )
        .unwrap()
    }

    pub fn reloc(&self, object: usize, section: usize, index: usize) -> Reloc {
        let start = self.objects[object].sections[section].relocs.start as usize + index * 10;
        Reloc::read(&self.object_data(object)[start..start + 10])
    }

    fn sort_candidates(&mut self) {
        let objects = &self.objects;
        let imports = &self.imports;
        for candidates in &mut self.candidates {
            candidates.sort_unstable_by_key(|target| match target.expand() {
                Target::Archive(o) => (objects[o].order, 0),
                Target::Symbol(o, s) => (objects[o].order, s),
                Target::Import(i, _) => (imports[i].order, 0),
                Target::ImageBase => (0, 0),
            });
            candidates.dedup();
        }
    }

    fn load_fallback_index(&mut self) -> Result<bool> {
        crate::timing_phase!("COFF fallback index");
        let members = std::mem::take(&mut self.fallback_members);
        if members.is_empty() {
            return Ok(false);
        }
        for o in members {
            if self.objects[o].active {
                continue;
            }
            let object = &self.objects[o];
            let data = &self.inputs[object.input].bytes()[object.range.clone()];
            let names: Vec<_> = input::archive_names(data, false)?
                .into_iter()
                .map(|name| self.names.intern(name))
                .collect();
            for id in names {
                self.add_candidate(id, Target::Archive(o));
            }
        }
        self.sort_candidates();
        Ok(true)
    }

    fn directive(&mut self, directive: &str) -> Result {
        let d = directive.trim_start_matches(['/', '-']);
        let (name, value) = d.split_once(':').unwrap_or((d, ""));
        match name.to_ascii_lowercase().as_str() {
            "defaultlib" => self.pending.push_back(value.to_owned()),
            "include" => {
                self.forced.insert(self.names.intern(value));
            }
            "alternatename" => {
                let (from, to) = value.split_once('=').context("Invalid /ALTERNATENAME")?;
                let from = self.names.intern(from);
                let to = self.names.intern(to);
                self.aliases.insert(from, to);
            }
            "failifmismatch" => {
                let (key, value) = value.split_once('=').context("Invalid /FAILIFMISMATCH")?;
                if let Some(old) = self.mismatches.insert(key.to_owned(), value.to_owned()) {
                    ensure!(old == value, "/FAILIFMISMATCH {key}: {old} vs {value}");
                }
            }
            "merge" => {
                let (from, to) = value.split_once('=').context("Invalid /MERGE")?;
                self.merges.insert(from.to_owned(), to.to_owned());
            }
            "section" => {
                let (name, flags) = value.split_once(',').context("Invalid /SECTION")?;
                ensure!(
                    flags
                        .chars()
                        .all(|c| "ERWDSKPN!".contains(c.to_ascii_uppercase())),
                    "Invalid /SECTION attributes"
                );
                self.section_flags
                    .insert(name.to_owned(), flags.to_ascii_uppercase());
            }
            "wholearchive" => {
                if value.is_empty() {
                    self.whole_archive = true;
                    let mut objects: Vec<_> =
                        self.archive_members.values().flatten().copied().collect();
                    objects.sort_unstable();
                    for object in objects {
                        self.activate(object)?;
                    }
                } else {
                    let path = self.find_library(value)?;
                    self.load_file(&path, true)?;
                }
            }
            "nodefaultlib" => {
                if value.is_empty() {
                    self.no_default_libraries = true;
                } else {
                    self.excluded_libraries.insert(library_name(value));
                }
            }
            "editandcontinue" | "disallowlib" => {}
            _ => bail!("Unsupported COFF directive {directive}"),
        }
        Ok(())
    }

    fn require(&mut self, name: NameId, depth: usize) -> Result<bool> {
        ensure!(depth < 64, "COFF alias cycle at {}", self.names.get(name));
        if self.names.get(name) == "__ImageBase" {
            return Ok(false);
        }
        if self.active_name(name) {
            return Ok(false);
        }
        if let Some(candidates) = self.candidates(name) {
            if candidates.iter().any(|t| match t.expand() {
                Target::Symbol(o, _) | Target::Archive(o) => self.objects[o].active,
                Target::Import(i, _) => self.imports[i].live,
                _ => true,
            }) {
                return Ok(false);
            }
            if let Some(target) = candidates.first() {
                match target.expand() {
                    Target::Symbol(o, _) | Target::Archive(o) => return self.activate(o),
                    Target::Import(i, _) => {
                        self.imports[i].live = true;
                        return Ok(true);
                    }
                    _ => {}
                }
            }
        }
        if let Some(alias) = self.aliases.get(&name).copied() {
            return self.require(alias, depth + 1);
        }
        Ok(false)
    }

    fn satisfied(&self, name: NameId, depth: usize) -> Result<bool> {
        ensure!(depth < 64, "COFF alias cycle at {}", self.names.get(name));
        if self.names.get(name) == "__ImageBase" || self.active_name(name) {
            return Ok(true);
        }
        if let Some(candidates) = self.candidates(name) {
            if candidates.iter().any(|t| match t.expand() {
                Target::Symbol(o, _) | Target::Archive(o) => self.objects[o].active,
                Target::Import(i, _) => self.imports[i].live,
                Target::ImageBase => true,
            }) {
                return Ok(true);
            }
        }
        if let Some(alias) = self.aliases.get(&name) {
            return self.satisfied(*alias, depth + 1);
        }
        Ok(false)
    }

    pub fn canonical(&self, mut o: usize, mut s: usize) -> (usize, usize) {
        for _ in 0..self.objects.len() + 1 {
            if let Some((no, ns)) = self.objects[o].sections[s].replacement {
                o = no as usize;
                s = ns as usize;
            } else {
                return (o, s);
            }
        }
        (o, s)
    }

    fn rebuild_definitions(&mut self) -> Result {
        self.definitions.clear();
        let image_base = self.names.intern("__ImageBase");
        self.definitions.resize(self.names.values.len(), None);
        self.definitions[image_base as usize] = Some(ResolvedTarget::compress(Target::ImageBase));
        for (o, object) in self.objects.iter().enumerate().filter(|(_, o)| o.active) {
            for (s, symbol) in object
                .symbols
                .iter()
                .enumerate()
                .filter(|(_, s)| s.definition())
            {
                if symbol.section > 0 {
                    let sec = symbol.section as usize - 1;
                    if self.canonical(o, sec) != (o, sec) {
                        continue;
                    }
                    if let Some(parent) = object.sections[sec].parent {
                        let parent = parent as usize;
                        if self.canonical(o, parent) != (o, parent) {
                            continue;
                        }
                    }
                }
                if let Some(Target::Symbol(old_o, old_s)) =
                    self.definitions[symbol.name_id as usize].map(ResolvedTarget::expand)
                {
                    let old = &self.objects[old_o].symbols[old_s];
                    if old.section != 0 && symbol.section == 0 {
                        continue;
                    }
                    if old.section > 0
                        && symbol.section > 0
                        && old.class != 105
                        && symbol.class != 105
                    {
                        bail!(
                            "Duplicate symbol {} in {} and {}",
                            self.symbol_name(o, s),
                            self.objects[old_o].name,
                            object.name
                        );
                    }
                    if old.section == 0 && symbol.section == 0 && old.value >= symbol.value {
                        continue;
                    }
                }
                self.definitions[symbol.name_id as usize] =
                    Some(ResolvedTarget::compress(Target::Symbol(o, s)));
            }
        }
        // COFF weak aliases are undefined symbols with a defined fallback. They
        // can satisfy archive lookups, but never override a strong definition.
        for (o, object) in self.objects.iter().enumerate().filter(|(_, o)| o.active) {
            for (s, symbol) in object.symbols.iter().enumerate() {
                if symbol.weak.is_some() {
                    self.definitions[symbol.name_id as usize]
                        .get_or_insert(ResolvedTarget::compress(Target::Symbol(o, s)));
                }
            }
        }
        for (i, import) in self.imports.iter().enumerate().filter(|(_, i)| i.live) {
            let iat = self
                .names
                .find(&format!("__imp_{}", import.symbol))
                .unwrap();
            self.definitions[iat as usize]
                .get_or_insert(ResolvedTarget::compress(Target::Import(i, true)));
            if import.code {
                let name = self.names.find(&import.symbol).unwrap();
                self.definitions[name as usize]
                    .get_or_insert(ResolvedTarget::compress(Target::Import(i, false)));
            }
        }
        Ok(())
    }

    pub fn target(&self, object: usize, symbol: usize) -> Result<Target> {
        if let Some(target) = self.objects[object].symbols[symbol].target {
            return Ok(target.expand());
        }
        self.target_inner(object, symbol, 0)
    }

    fn target_inner(&self, object: usize, symbol: usize, depth: usize) -> Result<Target> {
        ensure!(depth < 64, "Weak symbol cycle");
        let s = self.objects[object]
            .symbols
            .get(symbol)
            .context("Invalid relocation symbol index")?;
        if !s.external() && (s.section > 0 || s.section == -1) {
            return Ok(Target::Symbol(object, symbol));
        }
        let named = if s.external() {
            self.named_id_target(s.name_id, depth)?
        } else {
            self.named_target(self.symbol_name(object, symbol), depth)?
        };
        if let Some(t) = named {
            return Ok(t);
        }
        if let Some((fallback, _)) = s.weak() {
            return self.target_inner(object, fallback, depth + 1);
        }
        bail!(
            "Undefined symbol {} referenced by {}",
            self.symbol_name(object, symbol),
            self.objects[object].name
        )
    }

    pub fn named_target(&self, name: &str, depth: usize) -> Result<Option<Target>> {
        let Some(id) = self.names.find(name) else {
            return Ok(None);
        };
        self.named_id_target(id, depth)
    }

    fn named_id_target(&self, name: NameId, depth: usize) -> Result<Option<Target>> {
        ensure!(depth < 64, "Alias cycle at {}", self.names.get(name));
        if let Some(t) = self.definitions.get(name as usize).copied().flatten() {
            let t = t.expand();
            if let Target::Symbol(o, s) = t {
                let symbol = &self.objects[o].symbols[s];
                if let Some((fallback, _)) = symbol.weak() {
                    return self.target_inner(o, fallback, depth + 1).map(Some);
                }
            }
            return Ok(Some(t));
        }
        if let Some(alias) = self.aliases.get(&name) {
            return self.named_id_target(*alias, depth + 1);
        }
        Ok(None)
    }

    pub fn report_work_timing(&self) {
        if self.args.common.time_phase_options.is_some() {
            let _span = tracing::info_span!(
                "COFF accumulated work",
                parse_ms = self.work_timing.parse.load(Ordering::Relaxed) as f64 / 1_000_000.0,
                index_scan_ms =
                    self.work_timing.index_scan.load(Ordering::Relaxed) as f64 / 1_000_000.0,
                intern_ms = self.work_timing.intern.load(Ordering::Relaxed) as f64 / 1_000_000.0,
                selection_ms =
                    self.work_timing.selection.load(Ordering::Relaxed) as f64 / 1_000_000.0
            )
            .entered();
        }
    }

    pub fn resolve(&mut self) -> Result {
        let fixed_point_time = crate::timing_guard!(
            "COFF symbol resolution",
            threads = rayon::current_num_threads()
        );
        let mut unresolved: HashSet<NameId> = HashSet::from_iter([self.names.intern(&self.entry)]);
        loop {
            unresolved.extend(self.forced.iter().copied());
            let mut tls = false;
            while let Some(o) = self.newly_active.pop_front() {
                let object = &self.objects[o];
                tls |= object.sections.iter().any(|s| s.tls);
                for symbol in &object.symbols {
                    if symbol.external() && symbol.section == 0 && symbol.value == 0 {
                        if let Some((fallback, search)) = symbol.weak() {
                            if search != 1 {
                                unresolved.insert(symbol.name_id);
                            }
                            let fallback = object
                                .symbols
                                .get(fallback)
                                .context("Invalid weak fallback")?;
                            if fallback.section == 0 && fallback.value == 0 {
                                unresolved.insert(fallback.name_id);
                            }
                        } else {
                            unresolved.insert(symbol.name_id);
                        }
                    }
                }
            }
            if tls {
                unresolved.insert(self.names.intern("_tls_used"));
            }
            let mut changed = false;
            let mut needs: Vec<_> = unresolved
                .drain()
                .map(|id| (id, self.names.get(id)))
                .collect();
            let compare = |a: &(NameId, &str), b: &(NameId, &str)| a.1.cmp(b.1);
            if needs.len() >= 4096
                && rayon::current_num_threads() > 1
                && !self.args.common.num_threads.is_some_and(|n| n.get() == 1)
            {
                needs.par_sort_unstable_by(compare);
            } else {
                needs.sort_unstable_by(compare);
            }
            let needs: Vec<_> = needs.into_iter().map(|(id, _)| id).collect();
            self.prepare_members(&needs);
            for name in needs {
                changed |= self.require(name, 0)?;
                if !self.satisfied(name, 0)? {
                    unresolved.insert(name);
                }
            }
            changed |= self.load_pending()?;
            if !changed && !unresolved.is_empty() {
                changed |= self.load_fallback_index()?;
            }
            if !changed {
                break;
            }
        }
        self.prepared.clear();
        drop(fixed_point_time);
        {
            crate::timing_phase!("COFF definitions");
            self.rebuild_definitions()?;
        }
        crate::timing_phase!(
            "COFF GC",
            names = self.names.values.len(),
            local_comdats = self
                .objects
                .iter()
                .filter(|o| o.active)
                .flat_map(|o| &o.sections)
                .filter(|s| s.selection != 0 && s.selection != 5 && s.key_symbol.is_none())
                .count()
        );
        let entry = self
            .named_target(&self.entry, 0)?
            .with_context(|| format!("Entry point {} is undefined", self.entry))?;
        let mut queue = VecDeque::new();
        self.mark_target(entry, &mut queue)?;
        let mut forced: Vec<_> = self.forced.iter().copied().collect();
        forced.sort_unstable_by(|a, b| self.names.get(*a).cmp(self.names.get(*b)));
        for name in forced {
            let t = self.named_id_target(name, 0)?.with_context(|| {
                format!("/INCLUDE symbol {} is undefined", self.names.get(name))
            })?;
            self.mark_target(t, &mut queue)?;
        }
        if let Some(t) = self.named_target("_tls_used", 0)? {
            self.mark_target(t, &mut queue)?;
        }
        if let Some(t) = self.named_target("_load_config_used", 0)? {
            self.mark_target(t, &mut queue)?;
        }
        for o in 0..self.objects.len() {
            if !self.objects[o].active {
                continue;
            }
            for s in 0..self.objects[o].sections.len() {
                let sec = &self.objects[o].sections[s];
                if !sec.excluded() && (sec.selection == 0 || !self.args.gc || sec.crt || sec.tls) {
                    self.mark_section(o, s, &mut queue);
                }
            }
        }
        while let Some((o, s)) = queue.pop_front() {
            for i in 0..self.objects[o].sections[s].relocs.len() / 10 {
                let reloc = self.reloc(o, s, i);
                // A cached target has already been marked in this GC walk. Repeated
                // relocations to the same symbol do not need to chase its section again.
                if reloc.kind != 0 && self.objects[o].symbols[reloc.symbol].target.is_none() {
                    let target = self.target(o, reloc.symbol)?;
                    self.objects[o].symbols[reloc.symbol].target =
                        Some(ResolvedTarget::compress(target));
                    self.mark_target(target, &mut queue)?;
                }
            }
            let object = &self.objects[o];
            let children = object.child_offsets[s]..object.child_offsets[s + 1];
            for i in children {
                self.mark_section(o, self.objects[o].children[i], &mut queue);
            }
        }
        Ok(())
    }

    fn mark_section(
        &mut self,
        object: usize,
        section: usize,
        queue: &mut VecDeque<(usize, usize)>,
    ) {
        let (o, s) = self.canonical(object, section);
        if let Some(parent) = self.objects[o].sections[s].parent {
            let parent = parent as usize;
            if self.canonical(o, parent) != (o, parent) {
                return;
            }
        }
        let sec = &mut self.objects[o].sections[s];
        if sec.live || sec.excluded() {
            return;
        }
        sec.live = true;
        queue.push_back((o, s));
    }

    fn mark_target(&mut self, target: Target, queue: &mut VecDeque<(usize, usize)>) -> Result {
        if let Target::Symbol(o, s) = target {
            if self.objects[o].symbols[s].gc_marked {
                return Ok(());
            }
            self.objects[o].symbols[s].gc_marked = true;
            let symbol = &self.objects[o].symbols[s];
            if symbol.section > 0 {
                self.mark_section(o, symbol.section as usize - 1, queue);
            } else if symbol.section == 0 && symbol.value > 0 {
                let name = self.names.get(symbol.name_id).to_owned();
                self.commons
                    .entry(name)
                    .and_modify(|v| v.0 = v.0.max(symbol.value))
                    .or_insert((symbol.value, 0));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Names;

    #[test]
    fn interned_names_compare_bytes_even_when_hashes_collide() {
        let mut names = Names::default();
        let first = names.intern_hashed("first", 7);
        let second = names.intern_hashed("second", 7);
        assert_ne!(first, second);
        assert_eq!(names.intern_hashed("first", 7), first);
        assert_eq!(names.find_hashed("second", 7), Some(second));
        assert_eq!(names.find_hashed("missing", 7), None);
        assert_eq!(names.get(first), "first");
    }
}

fn library_name(name: &str) -> String {
    let name = Path::new(name)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    name.strip_suffix(".lib").unwrap_or(&name).to_owned()
}
