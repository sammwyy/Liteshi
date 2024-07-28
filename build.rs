use std::fs;
use std::path::Path;
use walkdir::WalkDir;
use yara_x::Compiler;

fn main() {
    let out_dir = Path::new("rules.bin");
    if out_dir.exists() {
        println!("Rules.bin already exist, skipping rules compilation.");
        return;
    }

    let rules_path = Path::new("rules");
    let mut compiler = Compiler::new();

    for entry in WalkDir::new(rules_path).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        let ext = path.extension().and_then(|s| s.to_str());
        let is_yara = ext == Some("yara") || ext == Some("yar");
        if path.is_file() && is_yara {
            let contents = fs::read_to_string(path).expect("Unable to read file");
            compiler
                .add_source(&*contents)
                .expect("Unable to add Yara source");
        }
    }

    let rules = compiler.build();
    let serialized_rules = rules.serialize().expect("Unable to serialize rules");
    fs::write(Path::new(&out_dir), serialized_rules)
        .expect("Unable to write serialized rules to file");
}
