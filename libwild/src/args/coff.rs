use crate::args::ArgumentParser;
use crate::args::CommonArgs;
use crate::args::Modifiers;
use crate::args::OptionSyntax;
use crate::bail;
use crate::error::Result;
use crate::platform;
use crate::platform::Args as _;
use std::path::Path;
use std::sync::Arc;

/// The only machine type we currently support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoffMachine {
    X86_64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Subsystem {
    Console,
    Windows,
}

#[derive(Debug)]
pub struct CoffArgs {
    pub(crate) common: CommonArgs,
    pub(crate) entry: Option<String>,
    pub(crate) subsystem: Option<Subsystem>,
    pub(crate) is_dll: bool,
    pub(crate) machine: CoffMachine,
    pub(crate) lib_search_path: Vec<Box<Path>>,
    pub(crate) default_libraries: Vec<String>,
    /// Libraries named by `/NODEFAULTLIB:name`.
    pub(crate) excluded_default_libraries: Vec<String>,
    /// Set by a bare `/NODEFAULTLIB`, which ignores every default library.
    pub(crate) no_default_libraries: bool,
    pub(crate) directives: Vec<String>,
    pub(crate) image_base: u64,
    pub(crate) stack: (u64, u64),
    pub(crate) heap: (u64, u64),
    pub(crate) gc: bool,
    pub(crate) nx_compat: bool,
    pub(crate) dynamic_base: bool,
    pub(crate) high_entropy_va: bool,
    pub(crate) large_address_aware: bool,
    pub(crate) subsystem_version: (u16, u16),
}

impl CoffArgs {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            common: CommonArgs::from_env()?,
            ..Default::default()
        })
    }
}

impl Default for CoffArgs {
    fn default() -> Self {
        Self {
            common: CommonArgs::default(),
            entry: None,
            subsystem: None,
            is_dll: false,
            machine: CoffMachine::X86_64,
            lib_search_path: Vec::new(),
            default_libraries: Vec::new(),
            excluded_default_libraries: Vec::new(),
            no_default_libraries: false,
            directives: Vec::new(),
            image_base: 0x140000000,
            stack: (1024 * 1024, 4096),
            heap: (1024 * 1024, 4096),
            gc: true,
            nx_compat: true,
            dynamic_base: true,
            high_entropy_va: true,
            large_address_aware: true,
            subsystem_version: (6, 0),
        }
    }
}

impl platform::Args for CoffArgs {
    fn parse<S, I>(&mut self, input: I) -> Result
    where
        S: AsRef<str>,
        I: Iterator<Item = S>,
    {
        parse(self, input)
    }

    fn should_strip_debug(&self) -> bool {
        true
    }

    fn should_strip_all(&self) -> bool {
        false
    }

    fn entry_point<'a>(
        &'a self,
        _linker_script_entry: Option<&'a [u8]>,
    ) -> platform::EntryPoint<'a> {
        self.entry
            .as_deref()
            .map_or(platform::EntryPoint::None, |entry| {
                platform::EntryPoint::Symbol(entry.as_bytes())
            })
    }

    fn lib_search_path(&self) -> &[Box<Path>] {
        &self.lib_search_path
    }

    fn common(&self) -> &CommonArgs {
        &self.common
    }

    fn common_mut(&mut self) -> &mut CommonArgs {
        &mut self.common
    }

    fn should_export_all_dynamic_symbols(&self) -> bool {
        false
    }

    fn should_export_dynamic(&self, _lib_name: &[u8]) -> bool {
        false
    }

    fn loadable_segment_alignment(&self) -> crate::alignment::Alignment {
        crate::alignment::Alignment { exponent: 12 }
    }

    fn should_merge_sections(&self) -> bool {
        !self.is_dll
    }

    fn should_output_executable(&self) -> bool {
        !self.is_dll
    }

    fn is_ignored_flag(&self, flag: &str) -> bool {
        // `flag` has had its prefix stripped, but still carries any attached value and the case the
        // user wrote, e.g. `WHOLEARCHIVE:foo.lib`.
        let name = flag.split_once(':').map_or(flag, |(name, _value)| name);

        IGNORED_FLAGS.contains(&name.to_ascii_lowercase().as_str())
    }
}

// Parse the supplied input arguments, which should not include the program name.
pub(crate) fn parse<S: AsRef<str>, I: Iterator<Item = S>>(args: &mut CoffArgs, input: I) -> Result {
    let mut modifier_stack = vec![Modifiers::default()];
    let raw: Vec<_> = input.map(|s| s.as_ref().to_owned()).collect();
    let expanded = expand_response_files(&raw, &mut Vec::new())?;
    let mut input = expanded.iter();
    let arg_parser = setup_argument_parser();
    while let Some(arg) = input.next() {
        let arg = arg.as_ref();

        arg_parser.handle_argument(args, &mut modifier_stack, arg, &mut input)?;
    }

    args.common.report_unrecognized()?;

    Ok(())
}

fn expand_response_files(
    input: &[String],
    stack: &mut Vec<std::path::PathBuf>,
) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for arg in input {
        if let Some(path) = arg.strip_prefix('@') {
            let path = std::fs::canonicalize(path)?;
            crate::ensure!(
                stack.len() < 32 && !stack.contains(&path),
                "Response-file cycle or nesting limit at {}",
                path.display()
            );
            stack.push(path.clone());
            out.extend(expand_response_files(&read_response_file(&path)?, stack)?);
            stack.pop();
        } else {
            out.push(arg.clone());
        }
    }
    Ok(out)
}

/// link.exe spells its options differently to the GNU-style linkers: names are case-insensitive,
/// take either a `/` or a `-` prefix and carry their value as `NAME:value`, with no separate-token
/// form.
const COFF_OPTION_SYNTAX: OptionSyntax = OptionSyntax {
    prefixes: &["/", "-"],
    value_separator: ':',
    case_insensitive: true,
    allows_separate_value: false,
};

/// Options that rustc's MSVC linker driver emits that we ignore without comment, because they
/// affect only outputs we don't produce yet, or because ignoring them already matches what we do.
/// These appear on virtually every link line, so warning about them would be pure noise. The value,
/// if any, is ignored too.
const SILENTLY_IGNORED_FLAGS: &[&str] = &[
    // PDB paths and debugger visualisers, which relate to debug info we don't emit.
    "pdb",
    "pdbaltpath",
    "natvis",
    // Manifest generation and warnings-as-errors, e.g. `/MANIFEST:EMBED`, `/MANIFESTUAC:NO`,
    // `/MANIFESTINPUT:foo.manifest`, `/WX:NO`.
    "manifest",
    "manifestinput",
    "manifestuac",
    "wx",
];

/// Options that we accept but that change either the output or the set of linked inputs when
/// ignored, so we warn rather than silently dropping them. These deliberately aren't declared on
/// the parser: leaving them undeclared routes them through the unrecognized-option fallback, which
/// reports them via [`platform::Args::is_ignored_flag`] with the spelling the user wrote. That
/// fallback passes the name with its value still attached, so `is_ignored_flag` splits it itself.
const IGNORED_FLAGS: &[&str] = &[
    // Control-flow guard, which we don't emit. `/DEBUG` is handled separately, since its `NONE`
    // value requests exactly what we do.
    "guard",
    // An import library and a module definition file, which we don't produce.
    "implib", "def",
];

/// Ignored options that take no value, so `/NOLOGO:x` is an error just like `/DLL:x` is.
const IGNORED_NO_VALUE_FLAGS: &[&str] = &["nologo"];

fn setup_argument_parser() -> ArgumentParser<CoffArgs> {
    let mut parser = ArgumentParser::<CoffArgs>::with_syntax(COFF_OPTION_SYNTAX);

    parser
        .declare_with_param()
        .long("out")
        .help("Set the output filename")
        .execute(|args, _modifier_stack, value| {
            args.common.output = Arc::from(Path::new(value));
            Ok(())
        });

    parser
        .declare_with_param()
        .long("entry")
        .help("Set the entry point symbol")
        .execute(|args, _modifier_stack, value| {
            args.entry = Some(value.to_owned());
            Ok(())
        });

    parser
        .declare_with_param()
        .long("subsystem")
        .help("Set the subsystem, optionally with a version")
        .execute(|args, _modifier_stack, value| {
            args.subsystem = Some(parse_subsystem(value)?);
            if let Some((_, version)) = value.split_once(',') {
                let (major, minor) = version.split_once('.').unwrap_or((version, "0"));
                args.subsystem_version = (major.parse()?, minor.parse()?);
            }
            Ok(())
        });

    parser
        .declare()
        .long("dll")
        .help("Build a DLL rather than an executable")
        .execute(|args, _modifier_stack| {
            args.is_dll = true;
            Ok(())
        });

    parser
        .declare_with_param()
        .long("machine")
        .help("Set the target machine")
        .execute(|args, _modifier_stack, value| {
            if !value.eq_ignore_ascii_case("x64") && !value.eq_ignore_ascii_case("amd64") {
                bail!("unsupported /MACHINE value `{value}`; only X64 is supported");
            }
            args.machine = CoffMachine::X86_64;
            Ok(())
        });

    parser
        .declare_with_param()
        .long("libpath")
        .help("Add directory to library search path")
        .execute(|args, _modifier_stack, value| {
            args.common.save_dir.handle_file(value);
            args.lib_search_path.push(Box::from(Path::new(value)));
            Ok(())
        });

    parser
        .declare_with_param()
        .long("defaultlib")
        .help("Add a default library")
        .execute(|args, _modifier_stack, value| {
            args.default_libraries.push(value.to_owned());
            Ok(())
        });

    // `/NODEFAULTLIB:lib` excludes one library, a bare `/NODEFAULTLIB` excludes all of them.
    // Precedence over `/DEFAULTLIB` is applied when default libraries are resolved.
    parser
        .declare_with_optional_param()
        .long("nodefaultlib")
        .help("Ignore one default library, or all of them if no library is named")
        .execute(|args, _modifier_stack, value| {
            match value {
                // An empty value is a malformed library name rather than a bare `/NODEFAULTLIB`.
                Some("") => bail!("missing value for /NODEFAULTLIB"),
                Some(value) => args.excluded_default_libraries.push(value.to_owned()),
                None => args.no_default_libraries = true,
            }
            Ok(())
        });

    // `/DEBUG:NONE` asks for no debug info, which is what we produce, so only the forms that
    // request a PDB warn.
    parser
        .declare_with_optional_param()
        .long("debug")
        .execute(|args, _modifier_stack, value| {
            match value {
                Some(value) if value.eq_ignore_ascii_case("none") => {}
                Some(value) => args.warn_unsupported(&format!("/DEBUG:{value}"))?,
                None => args.warn_unsupported("/DEBUG")?,
            }
            Ok(())
        });

    add_silently_ignored_flags(&mut parser);

    parser
        .declare()
        .long("-version")
        .long("version")
        .execute(|args, _| {
            args.common.version_mode = crate::args::VersionMode::ExitAfterPrint;
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("nxcompat")
        .execute(|args, _, value| {
            args.nx_compat = parse_boolean(value)?;
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("dynamicbase")
        .execute(|args, _, value| {
            args.dynamic_base = parse_boolean(value)?;
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("highentropyva")
        .execute(|args, _, value| {
            args.high_entropy_va = parse_boolean(value)?;
            Ok(())
        });
    parser
        .declare_with_optional_param()
        .long("largeaddressaware")
        .execute(|args, _, value| {
            args.large_address_aware = parse_boolean(value)?;
            Ok(())
        });

    macro_rules! directive {
        ($flag:literal) => {
            parser
                .declare_with_param()
                .long($flag)
                .execute(|args, _, value| {
                    args.directives
                        .push(format!(concat!("/", $flag, ":{}"), value));
                    Ok(())
                });
        };
    }
    directive!("include");
    directive!("alternatename");
    directive!("failifmismatch");
    directive!("merge");
    directive!("section");
    parser
        .declare_with_optional_param()
        .long("wholearchive")
        .execute(|args, _, value| {
            args.directives.push(
                value.map_or_else(|| "/wholearchive".into(), |v| format!("/wholearchive:{v}")),
            );
            Ok(())
        });
    parser
        .declare_with_param()
        .long("opt")
        .execute(|args, _, value| {
            for option in value.split(',') {
                match option.to_ascii_lowercase().as_str() {
                    "ref" => args.gc = true,
                    "noref" => args.gc = false,
                    "noicf" | "icf" => {}
                    _ => bail!("Unsupported /OPT value {option}"),
                }
            }
            Ok(())
        });
    parser
        .declare_with_param()
        .long("base")
        .execute(|args, _, value| {
            args.image_base = crate::args::parse_number(value)?;
            Ok(())
        });
    parser
        .declare_with_param()
        .long("stack")
        .execute(|args, _, value| {
            args.stack = parse_reserve_commit(value)?;
            Ok(())
        });
    parser
        .declare_with_param()
        .long("heap")
        .execute(|args, _, value| {
            args.heap = parse_reserve_commit(value)?;
            Ok(())
        });
    for flag in ["incremental", "brepro"] {
        parser
            .declare_with_optional_param()
            .long(flag)
            .execute(|_, _, _| Ok(()));
    }
    parser.declare().long("release").execute(|_, _| Ok(()));

    parser
}

fn parse_boolean(value: Option<&str>) -> Result<bool> {
    match value {
        None => Ok(true),
        Some(v) if v.eq_ignore_ascii_case("no") => Ok(false),
        _ => bail!("Expected a bare option or :NO"),
    }
}

fn parse_reserve_commit(value: &str) -> Result<(u64, u64)> {
    let (reserve, commit) = value.split_once(',').unwrap_or((value, "4096"));
    let reserve = crate::args::parse_number(reserve)?;
    let commit = crate::args::parse_number(commit)?;
    crate::ensure!(commit <= reserve, "Commit exceeds reserve");
    Ok((reserve, commit))
}

pub(crate) fn read_response_file(path: &Path) -> Result<Vec<String>> {
    let bytes = std::fs::read(path)?;
    let text = if bytes.starts_with(&[0xff, 0xfe]) {
        crate::ensure!(
            bytes.len() % 2 == 0,
            "Truncated UTF-16 response file {}",
            path.display()
        );
        String::from_utf16(
            &bytes[2..]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        )?
    } else {
        std::str::from_utf8(&bytes)?
            .trim_start_matches('\u{feff}')
            .to_owned()
    };
    split_windows_args(&text)
}

/// MSVC response files use the Windows backslash-before-quote convention.
pub(crate) fn split_windows_args(input: &str) -> Result<Vec<String>> {
    let mut args = Vec::new();
    let mut arg = String::new();
    let mut quoted = false;
    let mut started = false;
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let mut count = 1;
            while chars.peek() == Some(&'\\') {
                chars.next();
                count += 1;
            }
            if chars.peek() == Some(&'"') {
                arg.extend(std::iter::repeat_n('\\', count / 2));
                chars.next();
                if count % 2 == 1 {
                    arg.push('"');
                } else {
                    quoted = !quoted;
                }
            } else {
                arg.extend(std::iter::repeat_n('\\', count));
            }
            started = true;
        } else if c == '"' {
            quoted = !quoted;
            started = true;
        } else if c.is_whitespace() && !quoted {
            if started {
                args.push(std::mem::take(&mut arg));
                started = false;
            }
        } else {
            arg.push(c);
            started = true;
        }
    }
    crate::ensure!(!quoted, "Unclosed quote in Windows arguments");
    if started {
        args.push(arg);
    }
    Ok(args)
}

fn add_silently_ignored_flags(parser: &mut ArgumentParser<CoffArgs>) {
    for flag in SILENTLY_IGNORED_FLAGS {
        parser
            .declare_with_optional_param()
            .long(flag)
            .execute(|_args, _modifier_stack, _value| Ok(()));
    }

    for flag in IGNORED_NO_VALUE_FLAGS {
        parser
            .declare()
            .long(flag)
            .execute(|_args, _modifier_stack| Ok(()));
    }
}

/// Parses `/SUBSYSTEM:name[,major[.minor]]`. The version only sets optional-header fields we don't
/// emit yet, so it's validated and ignored.
fn parse_subsystem(value: &str) -> Result<Subsystem> {
    let (name, version) = value
        .split_once(',')
        .map_or((value, None), |(name, version)| (name, Some(version)));

    if let Some(version) = version {
        let (major, minor) = version
            .split_once('.')
            .map_or((version, None), |(major, minor)| (major, Some(minor)));

        if major.is_empty()
            || !major.bytes().all(|b| b.is_ascii_digit())
            || minor
                .is_some_and(|minor| minor.is_empty() || !minor.bytes().all(|b| b.is_ascii_digit()))
        {
            bail!("invalid /SUBSYSTEM version `{version}`; expected `major[.minor]`");
        }
    }

    match name.to_ascii_lowercase().as_str() {
        "console" => Ok(Subsystem::Console),
        "windows" => Ok(Subsystem::Windows),
        _ => bail!("unsupported subsystem `{name}`; only CONSOLE and WINDOWS are supported"),
    }
}

#[cfg(test)]
mod tests {
    use super::CoffArgs;
    use super::Subsystem;
    use super::parse;
    use crate::args::InputSpec;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::Mutex;

    /// A link line of the shape that rustc emits when targeting `x86_64-pc-windows-msvc`.
    const RUSTC_LINK_LINE: &[&str] = &[
        "/NOLOGO",
        "/OUT:target\\debug\\hello.exe",
        "/LIBPATH:sdk\\lib\\x64",
        "/DEFAULTLIB:msvcrt.lib",
        "/NODEFAULTLIB:libcmt.lib",
        "/SUBSYSTEM:CONSOLE",
        "/MACHINE:X64",
        "hello.o",
        "kernel32.lib",
    ];

    fn parse_args<'a>(args: impl IntoIterator<Item = &'a str>) -> CoffArgs {
        let mut coff_args = CoffArgs::default();
        parse(&mut coff_args, args.into_iter()).unwrap();
        coff_args
    }

    fn input_paths(args: &CoffArgs) -> Vec<&Path> {
        args.common
            .inputs
            .iter()
            .map(|input| match &input.spec {
                InputSpec::File(path) => path.as_ref(),
                InputSpec::Lib(_) | InputSpec::Search(_) => panic!("unexpected input spec"),
            })
            .collect()
    }

    #[test]
    fn parses_rustc_link_line() {
        let args = parse_args(RUSTC_LINK_LINE.iter().copied());

        assert_eq!(&*args.common.output, Path::new("target\\debug\\hello.exe"));
        assert_eq!(args.subsystem, Some(Subsystem::Console));
        assert_eq!(args.lib_search_path[0].as_ref(), Path::new("sdk\\lib\\x64"));
        assert_eq!(args.default_libraries, ["msvcrt.lib"]);
        assert_eq!(args.excluded_default_libraries, ["libcmt.lib"]);
        assert!(!args.no_default_libraries);
        assert!(!args.is_dll);
        assert_eq!(
            input_paths(&args),
            [Path::new("hello.o"), Path::new("kernel32.lib")]
        );
    }

    #[test]
    fn option_names_are_case_insensitive() {
        let args = parse_args(["/oUt:a.exe", "-ENTRY:main", "/dll"]);

        assert_eq!(&*args.common.output, Path::new("a.exe"));
        assert_eq!(args.entry.as_deref(), Some("main"));
        assert!(args.is_dll);
    }

    #[test]
    fn accepts_both_slash_and_dash_prefixes() {
        let slash = parse_args(["/OUT:a.exe", "/LIBPATH:lib"]);
        let dash = parse_args(["-OUT:a.exe", "-LIBPATH:lib"]);

        assert_eq!(slash.common.output, dash.common.output);
        assert_eq!(slash.lib_search_path, dash.lib_search_path);
    }

    fn parse_error<'a>(args: impl IntoIterator<Item = &'a str>) -> String {
        let mut coff_args = CoffArgs::default();
        parse(&mut coff_args, args.into_iter())
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn values_must_be_attached_to_the_option() {
        for arg in ["/OUT", "/ENTRY", "/LIBPATH", "/DEFAULTLIB", "/SUBSYSTEM"] {
            let message = parse_error([arg, "main.obj"]);
            assert!(
                message.contains("missing value for"),
                "for {arg}: {message}"
            );
        }

        let message = parse_error(["/OUT:", "/DLL", "main.obj"]);
        assert!(message.contains("missing value for /OUT"), "{message}");
    }

    #[test]
    fn empty_value_does_not_consume_the_following_token() {
        let message = parse_error(["/LIBPATH:", "main.obj"]);

        assert!(message.contains("missing value for /LIBPATH"), "{message}");
    }

    #[test]
    fn options_taking_no_value_reject_one() {
        for arg in ["/DLL:x", "/NOLOGO:x"] {
            let message = parse_error([arg]);
            assert!(
                message.contains("does not take a value"),
                "for {arg}: {message}"
            );
        }
    }

    #[test]
    fn unknown_options_with_a_dot_are_not_treated_as_inputs() {
        let message = parse_error(["/DEBUG.FOO"]);

        assert!(message.contains("unrecognized option(s)"), "{message}");
    }

    #[test]
    fn parses_subsystem_with_optional_version() {
        for arg in [
            "/SUBSYSTEM:windows",
            "/SUBSYSTEM:WINDOWS,6",
            "/SUBSYSTEM:windows,6.2",
        ] {
            assert_eq!(
                parse_args([arg]).subsystem,
                Some(Subsystem::Windows),
                "{arg}"
            );
        }
        for arg in ["/SUBSYSTEM:CONSOLE", "/subsystem:console,10.0"] {
            assert_eq!(
                parse_args([arg]).subsystem,
                Some(Subsystem::Console),
                "{arg}"
            );
        }

        let mut args = CoffArgs::default();
        let message = parse(&mut args, ["/SUBSYSTEM:CONSOLE,x"].into_iter())
            .unwrap_err()
            .to_string();
        assert!(message.contains("invalid /SUBSYSTEM version"), "{message}");
    }

    #[test]
    fn other_subsystems_are_unsupported_rather_than_unrecognized() {
        for name in ["NATIVE", "EFI_APPLICATION", "BOOT_APPLICATION", "POSIX"] {
            let mut args = CoffArgs::default();
            let message = parse(&mut args, [&format!("/SUBSYSTEM:{name}")].into_iter())
                .unwrap_err()
                .to_string();

            assert!(
                message.contains("unsupported subsystem"),
                "unexpected error for {name}: {message}"
            );
        }
    }

    #[test]
    fn rejects_machines_other_than_x64() {
        for machine in [
            "/MACHINE:X64",
            "/MACHINE:x64",
            "/MACHINE:amd64",
            "/machine:AMD64",
        ] {
            let mut args = CoffArgs::default();
            parse(&mut args, [machine].into_iter()).unwrap();
        }

        for machine in ["X86", "arm64", "ARM64EC", "arm64x", "ARM", "mips"] {
            let mut args = CoffArgs::default();
            let message = parse(&mut args, [&format!("/MACHINE:{machine}")].into_iter())
                .unwrap_err()
                .to_string();

            assert!(
                message.contains("only X64 is supported"),
                "unexpected error for {machine}: {message}"
            );
        }
    }

    #[test]
    fn bare_nodefaultlib_excludes_all_default_libraries() {
        let args = parse_args(["/NODEFAULTLIB"]);

        assert!(args.no_default_libraries);
        assert_eq!(args.excluded_default_libraries, Vec::<String>::new());
    }

    /// An empty value is a malformed library name, not the bare form, so link.exe rejects it.
    #[test]
    fn nodefaultlib_rejects_an_empty_value() {
        let message = parse_error(["/NODEFAULTLIB:"]);

        assert!(message.contains("missing value"), "{message}");
    }

    #[test]
    fn unknown_options_are_an_error() {
        for arg in ["/FOO", "-FOO:bar"] {
            let mut args = CoffArgs::default();
            let message = parse(&mut args, [arg].into_iter()).unwrap_err().to_string();

            assert!(
                message.contains("unrecognized option(s)"),
                "unexpected error for {arg}: {message}"
            );
        }
    }

    #[test]
    fn unknown_options_are_reported_together_with_valid_ones() {
        let mut args = CoffArgs::default();
        let message = parse(&mut args, ["/OUT:a.exe", "/FOO", "main.obj"].into_iter())
            .unwrap_err()
            .to_string();

        assert!(message.contains("/FOO"), "{message}");
    }

    /// Parses `args`, returning the parsed arguments along with any warnings that were emitted.
    fn parse_capturing_warnings<'a>(
        args: impl IntoIterator<Item = &'a str>,
    ) -> (CoffArgs, Vec<String>) {
        let mut coff_args = CoffArgs::default();
        let warnings = Arc::new(Mutex::new(Vec::new()));
        let warnings_clone = warnings.clone();
        coff_args.common.warning_callback = Box::new(move |warning| {
            warnings_clone
                .lock()
                .unwrap()
                .push(warning.warning().to_owned());
        });

        parse(&mut coff_args, args.into_iter()).unwrap();

        let warnings = warnings.lock().unwrap().clone();
        (coff_args, warnings)
    }

    #[test]
    fn rustc_silently_ignored_options_are_accepted() {
        let ignored = [
            "/NOLOGO",
            "/DEBUG:NONE",
            "/NXCOMPAT",
            "/NXCOMPAT:NO",
            "/DYNAMICBASE",
            "/DYNAMICBASE:NO",
            "/OPT:REF,NOICF",
            "/PDBALTPATH:%_PDB%",
            "/PDB:out.pdb",
            "/NATVIS:types.natvis",
            "/MANIFEST",
            "/MANIFEST:EMBED",
            "/MANIFEST:NO",
            "/MANIFESTINPUT:x/y.xml",
            "/MANIFESTUAC:NO",
            "/WX",
            "/WX:NO",
        ];

        for arg in ignored {
            let (args, warnings) = parse_capturing_warnings([arg, "main.obj"]);

            assert_eq!(input_paths(&args), [Path::new("main.obj")], "for {arg}");
            assert!(args.common.unrecognized_options.is_empty(), "for {arg}");
            assert!(
                warnings.is_empty(),
                "unexpected warning for {arg}: {warnings:?}"
            );
        }
    }

    #[test]
    fn unsupported_options_warn() {
        let unsupported = [
            "/DEBUG",
            "/DEBUG:FULL",
            "/IMPLIB:out.lib",
            "/DEF:exports.def",
            "/guard:cf",
        ];

        for arg in unsupported {
            let (args, warnings) = parse_capturing_warnings([arg, "main.obj"]);

            assert_eq!(input_paths(&args), [Path::new("main.obj")], "for {arg}");
            assert!(args.common.unrecognized_options.is_empty(), "for {arg}");
            // These spellings are already canonical, so both warning paths agree on the text.
            assert_eq!(
                warnings,
                [format!("{arg} is not yet supported")],
                "for {arg}"
            );
        }
    }

    /// The two warning paths quote the option differently. Flags in `IGNORED_FLAGS` reach
    /// `warn_unsupported` through the unrecognized-option fallback, which still has the whole
    /// argument, so they echo the user's spelling. `/DEBUG` is declared, so its handler sees only
    /// the value and has to rebuild the name in canonical form.
    #[test]
    fn warnings_quote_the_users_spelling_except_for_debug() {
        let (_args, warnings) = parse_capturing_warnings(["/implib:Foo.lib"]);
        assert_eq!(warnings, ["/implib:Foo.lib is not yet supported"]);

        let (_args, warnings) = parse_capturing_warnings(["/debug:full"]);
        assert_eq!(warnings, ["/DEBUG:full is not yet supported"]);
    }

    #[test]
    fn unsupported_options_warn_with_a_dash_prefix() {
        let (_args, warnings) = parse_capturing_warnings(["-IMPLIB:foo.lib"]);

        assert_eq!(warnings, ["-IMPLIB:foo.lib is not yet supported"]);
    }

    #[test]
    fn unknown_options_with_a_path_like_value_are_not_treated_as_inputs() {
        for arg in ["/BOGUSFLAG:a/b", "/BOGUSFLAG:a\\b"] {
            let message = parse_error([arg]);

            assert!(
                message.contains("unrecognized option(s)"),
                "unexpected error for {arg}: {message}"
            );
        }
    }

    #[test]
    fn options_whose_value_contains_a_separator_are_still_options() {
        let args = parse_args(["/LIBPATH:some/dir"]);

        assert_eq!(args.lib_search_path[0].as_ref(), Path::new("some/dir"));
        assert_eq!(args.common.inputs, []);
    }

    #[test]
    fn unprefixed_tokens_are_inputs() {
        let args = parse_args(["./x.obj", "foo.lib", "sub\\dir\\y.obj", "/OUT:a.exe"]);

        assert_eq!(
            input_paths(&args),
            [
                Path::new("./x.obj"),
                Path::new("foo.lib"),
                Path::new("sub\\dir\\y.obj")
            ]
        );
        assert_eq!(&*args.common.output, Path::new("a.exe"));
    }

    /// On Unix hosts, an absolute path starts with the same character as an option. link.exe has no
    /// such ambiguity, so we treat these as options and report them as unrecognized.
    #[test]
    fn unix_absolute_paths_are_treated_as_options() {
        let message = parse_error(["/tmp/foo.obj"]);

        assert!(message.contains("unrecognized option(s)"), "{message}");
    }

    #[test]
    fn bare_inputs_are_literal_paths() {
        // rustc passes libraries with the `.lib` suffix already applied, so we never append one.
        let args = parse_args(["foo", "foo.lib"]);

        assert_eq!(input_paths(&args), [Path::new("foo"), Path::new("foo.lib")]);
    }

    #[test]
    fn parses_full_rustc_style_link_line() {
        let args = parse_args([
            "/NOLOGO",
            "/NXCOMPAT",
            "/LIBPATH:C:\\lib",
            "main.o",
            "/OUT:main.exe",
            "/DEBUG",
            "/OPT:REF,NOICF",
            "/SUBSYSTEM:CONSOLE",
            "foo.lib",
        ]);

        assert_eq!(&*args.common.output, Path::new("main.exe"));
        assert_eq!(args.subsystem, Some(Subsystem::Console));
        assert_eq!(args.lib_search_path[0].as_ref(), Path::new("C:\\lib"));
        assert_eq!(
            input_paths(&args),
            [Path::new("main.o"), Path::new("foo.lib")]
        );
        assert_eq!(args.common.unrecognized_options, Vec::<String>::new());
        assert!(!args.is_dll);
    }
}
