use super::input::Import;
use super::input::Object;
use super::input::Parsed;
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
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::path::Path;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Target {
    Symbol(usize, usize),
    Import(usize, bool),
    ImageBase,
}

pub(super) struct Resolver<'a, F: FileSystem> {
    pub fs: &'a F,
    pub args: &'a CoffArgs,
    pub objects: Vec<Object>,
    pub imports: Vec<Import>,
    pub definitions: HashMap<String, Target>,
    pub commons: BTreeMap<String, (u32, u32)>,
    pub entry: String,
    candidates: HashMap<String, Vec<Target>>,
    selected: HashMap<String, (usize, usize)>,
    aliases: HashMap<String, String>,
    mismatches: HashMap<String, String>,
    forced: HashSet<String>,
    loaded: HashSet<PathBuf>,
    pending: VecDeque<String>,
    search: Vec<PathBuf>,
    pub merges: HashMap<String, String>,
    pub section_flags: HashMap<String, String>,
    excluded_libraries: HashSet<String>,
    no_default_libraries: bool,
    archive_members: HashMap<PathBuf, Vec<usize>>,
    whole_archive: bool,
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
            candidates: HashMap::new(),
            definitions: HashMap::new(),
            commons: BTreeMap::new(),
            entry: String::new(),
            selected: HashMap::new(),
            aliases: HashMap::new(),
            mismatches: HashMap::new(),
            forced: HashSet::new(),
            loaded: HashSet::new(),
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
            if self.candidates.contains_key("wmain") {
                "wmainCRTStartup".into()
            } else if self.candidates.contains_key("WinMain") {
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

    fn find_library(&self, name: &str) -> Result<PathBuf> {
        let mut path = PathBuf::from(name);
        if path.extension().is_none() {
            path.set_extension("lib");
        }
        self.find_file(&path)
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
        let data = bytes.bytes();
        if data.starts_with(b"!<arch>\n") {
            let first_object = self.objects.len();
            for member in crate::archive::ArchiveIterator::from_archive_bytes(data)? {
                let crate::archive::ArchiveEntry::Regular(member) = member? else {
                    bail!("Thin COFF archives are unsupported");
                };
                let member_name = std::str::from_utf8(member.ident.as_slice())?;
                let parsed = input::parse(member.entry_data, member_name.to_owned())
                    .with_context(|| format!("Reading {}({member_name})", path.display()))?;
                self.add(
                    parsed,
                    format!("{}({member_name})", path.display()),
                    whole || self.whole_archive,
                )?;
            }
            self.archive_members
                .insert(path, (first_object..self.objects.len()).collect());
        } else {
            self.add(
                input::parse(data, path.to_string_lossy().into_owned())?,
                path.to_string_lossy().into_owned(),
                true,
            )?;
        }
        Ok(true)
    }

    fn add(&mut self, parsed: Parsed, name: String, active: bool) -> Result {
        match parsed {
            Parsed::Metadata => {}
            Parsed::Import(import) => {
                let i = self.imports.len();
                self.candidates
                    .entry(format!("__imp_{}", import.symbol))
                    .or_default()
                    .push(Target::Import(i, true));
                if import.code {
                    self.candidates
                        .entry(import.symbol.clone())
                        .or_default()
                        .push(Target::Import(i, false));
                }
                self.imports.push(import);
            }
            Parsed::Object(mut object) => {
                object.name = name;
                for (s, section) in object.sections.iter_mut().enumerate() {
                    if section.key.starts_with("@local:") {
                        section.key = format!("{}#{s}", object.name);
                    }
                }
                let i = self.objects.len();
                for (s, symbol) in object.symbols.iter().enumerate() {
                    if symbol.definition() || symbol.weak.is_some() {
                        self.candidates
                            .entry(symbol.name.clone())
                            .or_default()
                            .push(Target::Symbol(i, s));
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
        self.objects[object].active = true;
        for i in 0..self.objects[object].sections.len() {
            let section = &self.objects[object].sections[i];
            if section.selection == 0 || section.selection == 5 {
                continue;
            }
            let key = section.key.clone();
            if let Some(&(old_obj, old_sec)) = self.selected.get(&key) {
                let old = &self.objects[old_obj].sections[old_sec];
                let replace = match section.selection {
                    1 => bail!(
                        "Duplicate NODUPLICATES COMDAT {key}: {} section {} and {} section {}",
                        self.objects[old_obj].name,
                        old_sec + 1,
                        self.objects[object].name,
                        i + 1
                    ),
                    2 => false,
                    3 => {
                        ensure!(old.size == section.size, "COMDAT size mismatch: {key}");
                        false
                    }
                    4 => {
                        let same_relocs = old.relocs.len() == section.relocs.len()
                            && old.relocs.iter().zip(&section.relocs).all(|(a, b)| {
                                a.offset == b.offset
                                    && a.kind == b.kind
                                    && self.objects[old_obj].symbols[a.symbol].name
                                        == self.objects[object].symbols[b.symbol].name
                            });
                        ensure!(
                            old.data == section.data && old.size == section.size && same_relocs,
                            "COMDAT content mismatch: {key}"
                        );
                        false
                    }
                    6 => section.size > old.size,
                    7 => true,
                    n => bail!("Unsupported COMDAT selection {n} for {key}"),
                };
                if replace {
                    self.objects[old_obj].sections[old_sec].replacement = Some((object, i));
                    self.selected.insert(key, (object, i));
                } else {
                    self.objects[object].sections[i].replacement = Some((old_obj, old_sec));
                }
            } else {
                self.selected.insert(key, (object, i));
            }
        }
        for d in self.objects[object].directives.clone() {
            self.directive(&d)?;
        }
        Ok(true)
    }

    fn directive(&mut self, directive: &str) -> Result {
        let d = directive.trim_start_matches(['/', '-']);
        let (name, value) = d.split_once(':').unwrap_or((d, ""));
        match name.to_ascii_lowercase().as_str() {
            "defaultlib" => self.pending.push_back(value.to_owned()),
            "include" => {
                self.forced.insert(value.to_owned());
            }
            "alternatename" => {
                let (from, to) = value.split_once('=').context("Invalid /ALTERNATENAME")?;
                self.aliases.insert(from.to_owned(), to.to_owned());
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
                    let objects: Vec<_> =
                        self.archive_members.values().flatten().copied().collect();
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

    fn require(&mut self, name: &str, depth: usize) -> Result<bool> {
        ensure!(depth < 64, "COFF alias cycle at {name}");
        if name == "__ImageBase" {
            self.definitions.insert(name.into(), Target::ImageBase);
            return Ok(false);
        }
        if let Some(candidates) = self.candidates.get(name).cloned() {
            if candidates.iter().any(|t| match *t {
                Target::Symbol(o, _) => self.objects[o].active,
                Target::Import(i, _) => self.imports[i].live,
                _ => true,
            }) {
                return Ok(false);
            }
            for target in candidates {
                match target {
                    Target::Symbol(o, _) => return self.activate(o),
                    Target::Import(i, _) => {
                        self.imports[i].live = true;
                        return Ok(true);
                    }
                    _ => {}
                }
            }
        }
        if let Some(alias) = self.aliases.get(name).cloned() {
            return self.require(&alias, depth + 1);
        }
        Ok(false)
    }

    pub fn canonical(&self, mut o: usize, mut s: usize) -> (usize, usize) {
        for _ in 0..self.objects.len() + 1 {
            if let Some((no, ns)) = self.objects[o].sections[s].replacement {
                o = no;
                s = ns;
            } else {
                return (o, s);
            }
        }
        (o, s)
    }

    fn rebuild_definitions(&mut self) -> Result {
        self.definitions.clear();
        self.definitions
            .insert("__ImageBase".into(), Target::ImageBase);
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
                        if self.canonical(o, parent) != (o, parent) {
                            continue;
                        }
                    }
                }
                if let Some(Target::Symbol(old_o, old_s)) =
                    self.definitions.get(&symbol.name).copied()
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
                            symbol.name,
                            self.objects[old_o].name,
                            object.name
                        );
                    }
                    if old.section == 0 && symbol.section == 0 && old.value >= symbol.value {
                        continue;
                    }
                }
                self.definitions
                    .insert(symbol.name.clone(), Target::Symbol(o, s));
            }
        }
        // COFF weak aliases are undefined symbols with a defined fallback. They
        // can satisfy archive lookups, but never override a strong definition.
        for (o, object) in self.objects.iter().enumerate().filter(|(_, o)| o.active) {
            for (s, symbol) in object.symbols.iter().enumerate() {
                if symbol.weak.is_some() {
                    self.definitions
                        .entry(symbol.name.clone())
                        .or_insert(Target::Symbol(o, s));
                }
            }
        }
        for (i, import) in self.imports.iter().enumerate().filter(|(_, i)| i.live) {
            self.definitions
                .entry(format!("__imp_{}", import.symbol))
                .or_insert(Target::Import(i, true));
            if import.code {
                self.definitions
                    .entry(import.symbol.clone())
                    .or_insert(Target::Import(i, false));
            }
        }
        Ok(())
    }

    pub fn target(&self, object: usize, symbol: usize) -> Result<Target> {
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
        if let Some(t) = self.named_target(&s.name, depth)? {
            return Ok(t);
        }
        if let Some((fallback, _)) = s.weak {
            return self.target_inner(object, fallback, depth + 1);
        }
        bail!(
            "Undefined symbol {} referenced by {}",
            s.name,
            self.objects[object].name
        )
    }

    pub fn named_target(&self, name: &str, depth: usize) -> Result<Option<Target>> {
        ensure!(depth < 64, "Alias cycle at {name}");
        if let Some(t) = self.definitions.get(name) {
            if let Target::Symbol(o, s) = *t {
                let symbol = &self.objects[o].symbols[s];
                if let Some((fallback, _)) = symbol.weak {
                    return self.target_inner(o, fallback, depth + 1).map(Some);
                }
            }
            return Ok(Some(*t));
        }
        if let Some(alias) = self.aliases.get(name) {
            return self.named_target(alias, depth + 1);
        }
        Ok(None)
    }

    pub fn resolve(&mut self) -> Result {
        loop {
            let mut needs: Vec<String> = self.forced.iter().cloned().collect();
            needs.push(self.entry.clone());
            let mut tls = false;
            for object in self.objects.iter().filter(|o| o.active) {
                tls |= object.sections.iter().any(|s| s.name.starts_with(".tls"));
                for symbol in &object.symbols {
                    if symbol.external() && symbol.section == 0 && symbol.value == 0 {
                        if let Some((fallback, search)) = symbol.weak {
                            if search != 1 {
                                needs.push(symbol.name.clone());
                            }
                            needs.push(
                                object
                                    .symbols
                                    .get(fallback)
                                    .context("Invalid weak fallback")?
                                    .name
                                    .clone(),
                            );
                        } else {
                            needs.push(symbol.name.clone());
                        }
                    }
                }
            }
            if tls {
                needs.push("_tls_used".into());
            }
            needs.sort();
            needs.dedup();
            let mut changed = false;
            for name in needs {
                changed |= self.require(&name, 0)?;
            }
            changed |= self.load_pending()?;
            if !changed {
                break;
            }
        }
        self.rebuild_definitions()?;
        let entry = self
            .named_target(&self.entry, 0)?
            .with_context(|| format!("Entry point {} is undefined", self.entry))?;
        let mut queue = VecDeque::new();
        self.mark_target(entry, &mut queue)?;
        for name in self.forced.clone() {
            let t = self
                .named_target(&name, 0)?
                .with_context(|| format!("/INCLUDE symbol {name} is undefined"))?;
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
                if !sec.excluded()
                    && (sec.selection == 0
                        || !self.args.gc
                        || sec.name.starts_with(".CRT$")
                        || sec.name.starts_with(".tls"))
                {
                    self.mark_section(o, s, &mut queue);
                }
            }
        }
        while let Some((o, s)) = queue.pop_front() {
            for reloc in self.objects[o].sections[s].relocs.clone() {
                if reloc.kind != 0 {
                    self.mark_target(self.target(o, reloc.symbol)?, &mut queue)?;
                }
            }
            for child in 0..self.objects[o].sections.len() {
                if self.objects[o].sections[child].parent == Some(s) {
                    self.mark_section(o, child, &mut queue);
                }
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
            let symbol = &self.objects[o].symbols[s];
            if symbol.section > 0 {
                self.mark_section(o, symbol.section as usize - 1, queue);
            } else if symbol.section == 0 && symbol.value > 0 {
                self.commons
                    .entry(symbol.name.clone())
                    .and_modify(|v| v.0 = v.0.max(symbol.value))
                    .or_insert((symbol.value, 0));
            }
        }
        Ok(())
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
