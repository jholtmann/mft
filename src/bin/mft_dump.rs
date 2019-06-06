use clap::{App, Arg, ArgMatches};
use indoc::indoc;
use log::Level;

use mft::attribute::MftAttributeType;
use mft::mft::MftParser;
use mft::{MftEntry, ReadSeek};

use dialoguer::Confirmation;
use mft::csv::FlatMftEntryWithName;

use snafu::ErrorCompat;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::exit;

use mft::entry::ZERO_HEADER;
use std::fmt::Write as FmtWrite;
use std::ops::RangeInclusive;
use std::str::FromStr;
use std::{fs, io, path};

/// Simple error macro for use inside of internal errors in `MftDump`
macro_rules! err {
    ($($tt:tt)*) => { Err(Box::<dyn std::error::Error>::from(format!($($tt)*))) }
}

type StdErr = Box<dyn std::error::Error>;

#[derive(Debug, PartialOrd, PartialEq)]
enum OutputFormat {
    JSON,
    JSONL,
    CSV,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "json" => Some(OutputFormat::JSON),
            "jsonl" => Some(OutputFormat::JSONL),
            "csv" => Some(OutputFormat::CSV),
            _ => None,
        }
    }
}

struct Ranges(Vec<RangeInclusive<usize>>);

impl Ranges {
    pub fn chain(&self) -> impl Iterator<Item = usize> + '_ {
        self.0.iter().cloned().flatten()
    }
}

impl FromStr for Ranges {
    type Err = StdErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut ranges = vec![];
        for x in s.split(',') {
            // range
            if x.contains('-') {
                let range: Vec<&str> = x.split('-').collect();
                if range.len() != 2 {
                    return err!(
                        "Failed to parse ranges: Range should contain exactly one `-`, found {}",
                        x
                    );
                }

                ranges.push(range[0].parse()?..=range[1].parse()?);
            } else {
                let n = x.parse()?;
                ranges.push(n..=n);
            }
        }

        Ok(Ranges(ranges))
    }
}

#[cfg(test)]
mod tests {
    use super::Ranges;
    use std::str::FromStr;

    #[test]
    fn it_works_with_single_number() {
        let ranges = Ranges::from_str("1").unwrap();
        assert_eq!(ranges.0, vec![1..=1]);
    }

    #[test]
    fn it_works_with_a_range() {
        let ranges = Ranges::from_str("1-5").unwrap();
        assert_eq!(ranges.0, vec![1..=5]);
    }

    #[test]
    fn it_works_with_a_range_and_a_number() {
        let ranges = Ranges::from_str("1-5,8").unwrap();
        assert_eq!(ranges.0, vec![1..=5, 8..=8]);
    }

    #[test]
    fn it_works_with_a_number_and_a_range() {
        let ranges = Ranges::from_str("1-5,8").unwrap();
        assert_eq!(ranges.0, vec![1..=5, 8..=8]);
    }

    #[test]
    fn it_works_with_more_than_2_number_and_a_range() {
        let ranges = Ranges::from_str("1-5,8,10-19").unwrap();
        assert_eq!(ranges.0, vec![1..=5, 8..=8, 10..=19]);
    }

    #[test]
    fn it_works_with_two_ranges() {
        let ranges = Ranges::from_str("1-10,20-25").unwrap();
        assert_eq!(ranges.0, vec![1..=10, 20..=25]);
    }

    #[test]
    fn it_errors_on_a_random_string() {
        let ranges = Ranges::from_str("hello");
        assert!(ranges.is_err())
    }

    #[test]
    fn it_errors_on_a_range_with_too_many_dashes() {
        let ranges = Ranges::from_str("1-5-8");
        assert!(ranges.is_err())
    }
}

struct MftDump {
    filepath: PathBuf,
    // We use an option here to be able to move the output out of mftdump from a mutable reference.
    output: Option<Box<dyn Write>>,
    data_streams_output: Option<PathBuf>,
    verbosity_level: Option<Level>,
    output_format: OutputFormat,
    ranges: Option<Ranges>,
    backtraces: bool,
}

impl MftDump {
    pub fn from_cli_matches(matches: &ArgMatches) -> Result<Self, StdErr> {
        let output_format =
            OutputFormat::from_str(matches.value_of("output-format").unwrap_or_default())
                .expect("Validated with clap default values");

        let backtraces = matches.is_present("backtraces");

        let output: Option<Box<dyn Write>> = if let Some(path) = matches.value_of("output-target") {
            match Self::create_output_file(path, !matches.is_present("no-confirm-overwrite")) {
                Ok(f) => Some(Box::new(f)),
                Err(e) => {
                    return err!(
                        "An error occurred while creating output file at `{}` - `{}`",
                        path,
                        e
                    );
                }
            }
        } else {
            Some(Box::new(io::stdout()))
        };

        let data_streams_output = if let Some(path) = matches.value_of("data-streams-target") {
            let path = PathBuf::from(path);
            Self::create_output_dir(&path)?;
            Some(path)
        } else {
            None
        };

        let verbosity_level = match matches.occurrences_of("verbose") {
            0 => None,
            1 => Some(Level::Info),
            2 => Some(Level::Debug),
            3 => Some(Level::Trace),
            _ => {
                eprintln!("using more than  -vvv does not affect verbosity level");
                Some(Level::Trace)
            }
        };

        let ranges = match matches.value_of("entry-range") {
            Some(range) => Some(Ranges::from_str(range)?),
            None => None,
        };

        Ok(MftDump {
            filepath: PathBuf::from(matches.value_of("INPUT").expect("Required argument")),
            output,
            data_streams_output,
            verbosity_level,
            output_format,
            ranges,
            backtraces,
        })
    }

    fn create_output_dir(path: impl AsRef<Path>) -> Result<(), StdErr> {
        let p = path.as_ref();

        if p.exists() {
            if !p.is_dir() {
                return err!("There is a file at {}, refusing to overwrite", p.display());
            }
        // p exists and is a directory, it's ok to add files.
        } else {
            fs::create_dir_all(path)?
        }

        Ok(())
    }

    /// If `prompt` is passed, will display a confirmation prompt before overwriting files.
    fn create_output_file(
        path: impl AsRef<Path>,
        prompt: bool,
    ) -> Result<File, Box<dyn std::error::Error>> {
        let p = path.as_ref();

        if p.is_dir() {
            return err!(
                "There is a directory at {}, refusing to overwrite",
                p.display()
            );
        }

        if p.exists() {
            if prompt {
                match Confirmation::new()
                    .with_text(&format!(
                        "Are you sure you want to override output file at {}",
                        p.display()
                    ))
                    .default(false)
                    .interact()
                {
                    Ok(true) => Ok(File::create(p)?),
                    Ok(false) => err!("Cancelled"),
                    Err(e) => err!(
                        "Failed to write confirmation prompt to term caused by\n{}",
                        e
                    ),
                }
            } else {
                Ok(File::create(p)?)
            }
        } else {
            // Ok to assume p is not an existing directory
            match p.parent() {
                Some(parent) =>
                // Parent exist
                {
                    if parent.exists() {
                        Ok(File::create(p)?)
                    } else {
                        fs::create_dir_all(parent)?;
                        Ok(File::create(p)?)
                    }
                }
                None => err!("Output file cannot be root."),
            }
        }
    }

    /// Main entry point for `EvtxDump`
    pub fn run(&mut self) -> Result<(), StdErr> {
        self.try_to_initialize_logging();

        let mut parser = match MftParser::from_path(&self.filepath) {
            Ok(parser) => parser,
            Err(e) => {
                return err!(
                    "Failed to open file {}.\n\tcaused by: {}",
                    self.filepath.display(),
                    &e
                )
            }
        };

        // Since the JSON parser can do away with a &mut Write, but the csv parser needs ownership
        // of `Write`, we eagerly create the csv writer here, moving the Box<Write> out from
        // `Mftdump` and replacing it with None placeholder.
        let mut csv_writer = match self.output_format {
            OutputFormat::CSV => {
                Some(csv::Writer::from_writer(self.output.take().expect(
                    "There can only be one flow accessing the output at a time",
                )))
            }
            _ => None,
        };

        let number_of_entries = parser.get_entry_count();

        // Move ranges out of self here to avoid immutably locking self during
        // the `for i in entries` loop.
        let take_ranges = self.ranges.take();

        let entries = match take_ranges {
            Some(ref ranges) => Box::new(ranges.chain()),
            None => Box::new(0..number_of_entries as usize) as Box<dyn Iterator<Item = usize>>,
        };

        for i in entries {
            let entry = parser.get_entry(i as u64);

            let entry = match entry {
                Ok(entry) => match &entry.header.signature {
                    ZERO_HEADER => continue,
                    _ => entry,
                },
                Err(error) => {
                    eprintln!("{}", error);

                    if self.backtraces {
                        if let Some(bt) = error.backtrace() {
                            eprintln!("{}", bt);
                        }
                    }
                    continue;
                }
            };

            if let Some(data_streams_dir) = &self.data_streams_output {
                if let Ok(Some(path)) = parser.get_full_path_for_entry(&entry) {
                    let sanitized_path = sanitized(&path.to_string_lossy().to_string());

                    for (i, (name, stream)) in entry
                        .iter_attributes()
                        .filter_map(|a| a.ok())
                        .filter_map(|a| {
                            if a.header.type_code == MftAttributeType::DATA {
                                // resident
                                let name = a.header.name.clone();
                                if let Some(data) = a.data.into_data() {
                                    Some((name, data))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        })
                        .enumerate()
                    {
                        let orig_path_component: String = data_streams_dir
                            .join(&sanitized_path)
                            .to_string_lossy()
                            .to_string();

                        // Add some random bits to prevent collisions
                        let random: [u8; 6] = rand::random();
                        let rando_string: String = to_hex_string(&random);

                        let truncated: String = orig_path_component.chars().take(150).collect();
                        let data_stream_path = format!(
                            "{path}__{random}_{stream_number}_{stream_name}.dontrun",
                            path = truncated,
                            random = rando_string,
                            stream_number = i,
                            stream_name = name
                        );

                        if PathBuf::from(&data_stream_path).exists() {
                            return err!(
                                "Tried to override an existing stream {} already exists!\
                                 This is a bug, please report to github!",
                                data_stream_path
                            );
                        }

                        let mut f = File::create(&data_stream_path)?;
                        f.write_all(stream.data())?;
                    }
                }
            }

            match self.output_format {
                OutputFormat::JSON | OutputFormat::JSONL => self.print_json_entry(&entry)?,
                OutputFormat::CSV => self.print_csv_entry(
                    &entry,
                    &mut parser,
                    csv_writer
                        .as_mut()
                        .expect("CSV Writer is for OutputFormat::CSV"),
                )?,
            }
        }

        Ok(())
    }

    fn try_to_initialize_logging(&self) {
        if let Some(level) = self.verbosity_level {
            match simplelog::WriteLogger::init(
                level.to_level_filter(),
                simplelog::Config::default(),
                io::stderr(),
            ) {
                Ok(_) => {}
                Err(e) => eprintln!("Failed to initialize logging: {}", e.description()),
            };
        }
    }

    pub fn print_json_entry(&mut self, entry: &MftEntry) -> Result<(), Box<dyn std::error::Error>> {
        let out = self
            .output
            .as_mut()
            .expect("CSV Flow cannot occur, so `Mftdump` should still Own `output`");

        let json_str = if self.output_format == OutputFormat::JSON {
            serde_json::to_vec_pretty(&entry).expect("It should be valid UTF-8")
        } else {
            serde_json::to_vec(&entry).expect("It should be valid UTF-8")
        };

        out.write_all(&json_str)?;
        out.write_all(b"\n")?;

        Ok(())
    }

    pub fn print_csv_entry<W: Write>(
        &self,
        entry: &MftEntry,
        parser: &mut MftParser<impl ReadSeek>,
        writer: &mut csv::Writer<W>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let flat_entry = FlatMftEntryWithName::from_entry(&entry, parser);

        writer.serialize(flat_entry)?;

        Ok(())
    }
}

fn to_hex_string(bytes: &[u8]) -> String {
    let len = bytes.len();
    // Each byte is represented by 2 ascii bytes.
    let mut s = String::with_capacity(len * 2);

    for byte in bytes {
        write!(s, "{:02X}", byte).expect("Writing to an allocated string cannot fail");
    }

    s
}

// adapter from python version
// https://github.com/pallets/werkzeug/blob/9394af646038abf8b59d6f866a1ea5189f6d46b8/src/werkzeug/utils.py#L414
pub fn sanitized(component: &str) -> String {
    let mut buf = String::with_capacity(component.len());
    for c in component.chars() {
        match c {
            _sep if path::is_separator(c) => buf.push('_'),
            _ => buf.push(c),
        }
    }

    buf
}

fn main() {
    let matches = App::new("MFT Parser")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Omer B. <omerbenamram@gmail.com>")
        .about("Utility for parsing MFT snapshots")
        .arg(Arg::with_name("INPUT").required(true))
        .arg(
            Arg::with_name("output-format")
                .short("-o")
                .long("--output-format")
                .takes_value(true)
                .possible_values(&["csv", "json", "jsonl"])
                .default_value("json")
                .help("Output format."),
        )
        .arg(
            Arg::with_name("entry-range")
                .long("--ranges")
                .short("-r")
                .takes_value(true)
                .help(indoc!("Dumps only the given entry range(s), for example, `1-15,30` will dump entries 1-15, and 30")),
        )
        .arg(
            Arg::with_name("output-target")
                .long("--output")
                .short("-f")
                .takes_value(true)
                .help(indoc!("Writes output to the file specified instead of stdout, errors will still be printed to stderr.
                       Will ask for confirmation before overwriting files, to allow overwriting, pass `--no-confirm-overwrite`
                       Will create parent directories if needed.")),
        )
        .arg(
            Arg::with_name("data-streams-target")
                .long("--extract-resident-streams")
                .short("-e")
                .takes_value(true)
                .help(indoc!("Writes resident data streams to the given directory.
                             Resident streams will be named like - `{path}__<random_bytes>_{stream_number}_{stream_name}.dontrun`
                             random is added to prevent collisions.")),
        )
        .arg(
            Arg::with_name("no-confirm-overwrite")
                .long("--no-confirm-overwrite")
                .takes_value(false)
                .help(indoc!("When set, will not ask for confirmation before overwriting files, useful for automation")),
        )
        .arg(Arg::with_name("verbose")
            .short("-v")
            .multiple(true)
            .takes_value(false)
            .help(indoc!(r#"
            Sets debug prints level for the application:
                -v   - info
                -vv  - debug
                -vvv - trace
            NOTE: trace output is only available in debug builds, as it is extremely verbose."#))
        )
        .arg(
            Arg::with_name("backtraces")
                .long("--backtraces")
                .takes_value(false)
                .help("If set, a backtrace will be printed with some errors if available"))
        .get_matches();

    let mut app = match MftDump::from_cli_matches(&matches) {
        Ok(app) => app,
        Err(e) => {
            eprintln!("An error occurred while setting up the app: {}", &e);
            exit(1);
        }
    };

    match app.run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("A runtime error has occurred: {}", &e);
            exit(1);
        }
    };
}
