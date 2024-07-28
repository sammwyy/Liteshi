use clap::Parser;
use colored::*;
use serde::Serialize;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::Instant;
use tracing::{error, info, Level};
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::FmtSubscriber;
use walkdir::WalkDir;
use yara_x::{Compiler, Rules, Scanner};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Directory or file containing Yara rules
    #[arg(short, long, value_name = "YARA")]
    yara: Option<PathBuf>,

    /// Show only one matching rule
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    single: bool,

    /// Show results in JSON format
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    json: bool,

    /// Show results without color
    #[arg(long, action = clap::ArgAction::SetTrue)]
    no_color: bool,

    /// File(s) to scan
    files: Vec<PathBuf>,
}

#[derive(Serialize)]
struct ScanResult<'a> {
    file: &'a Path,
    matches: Vec<String>,
}

fn compile_rules_from_dir(rules_dir: &Path) -> Result<Rules, Box<dyn std::error::Error>> {
    let mut compiler = Compiler::new();

    for entry in WalkDir::new(rules_dir).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        let ext = path.extension().and_then(|s| s.to_str());
        let is_yara = ext == Some("yara") || ext == Some("yar");
        if path.is_file() && is_yara {
            let mut file = File::open(&path)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            compiler.add_source(&*contents)?;
        }
    }

    let rules = compiler.build();
    Ok(rules)
}

fn compile_rules_from_file(rules_file: &Path) -> Result<Rules, Box<dyn std::error::Error>> {
    let rules_data = fs::read(rules_file)?;
    let rules = Rules::deserialize(&rules_data)?;
    Ok(rules)
}

fn main() -> io::Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_timer(ChronoLocal::new(String::from("%H:%M:%S")))
        .compact()
        .with_thread_names(false)
        .with_thread_ids(false)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    // Measure rule load time
    let rule_start_time = Instant::now();

    // Parse arguments
    let args = Args::parse();

    if !args.json {
        info!("Starting scan with settings:");
        info!("  * Files: {}", args.files.len());
        info!("  * Single: {}", args.single);
        info!("  * Yara: {}", args.yara.is_some());
    }

    // Check if files are provided
    if args.files.is_empty() {
        error!("No files provided for scanning.");
        exit(1);
    }

    let rules = match &args.yara {
        Some(yara_path) => {
            if yara_path.is_dir() {
                compile_rules_from_dir(yara_path).expect("Failed to compile rules from directory")
            } else {
                compile_rules_from_file(yara_path).expect("Failed to compile rules from file")
            }
        }
        None => {
            let built_in_rules: &[u8] = include_bytes!("../rules.bin");
            Rules::deserialize(built_in_rules).expect("Failed to deserialize built-in rules")
        }
    };

    let mut scanner = Scanner::new(&rules);

    if !args.json {
        let rule_elapsed_time = rule_start_time.elapsed();
        info!(
            "Engine initialized in {}",
            format!("{:.2?}", rule_elapsed_time).cyan()
        );
    }

    let start_time = Instant::now();

    let mut results = Vec::new();
    let mut trigger_count = 0;
    for file_path in &args.files {
        let mut file = File::open(&file_path)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        let scan_results = scanner.scan(&contents).unwrap();
        let matching_rules: Vec<String> = scan_results
            .matching_rules()
            .map(|rule| rule.identifier().to_string())
            .collect();

        if !matching_rules.is_empty() {
            trigger_count += matching_rules.len();
            results.push(ScanResult {
                file: file_path,
                matches: matching_rules.clone(),
            });

            if args.json {
                let json_result = serde_json::to_string(&ScanResult {
                    file: file_path,
                    matches: if args.single {
                        matching_rules.into_iter().take(1).collect()
                    } else {
                        matching_rules
                    },
                })
                .unwrap();
                println!("{}", json_result);
            } else {
                if args.no_color {
                    info!("Triggered: {}", file_path.display());

                    for rule in matching_rules {
                        info!("  * {}", rule);

                        if args.single {
                            break;
                        }
                    }
                } else {
                    info!(
                        "{} {}",
                        "Triggered:".bold().red(),
                        file_path.display().to_string().bold().cyan()
                    );

                    for rule in matching_rules {
                        info!("  {} {}", "*".bold().red(), rule.yellow());

                        if args.single {
                            break;
                        }
                    }
                }
            }

            if args.single {
                break;
            }
        }
    }

    let elapsed_time = start_time.elapsed();

    info!(
        "All tasks finished in {}, {} rules triggered.",
        format!("{:.2?}", elapsed_time).cyan(),
        format!("{:?}", trigger_count).bold().red()
    );

    Ok(())
}
