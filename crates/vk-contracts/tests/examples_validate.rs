use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts")
}

fn validator_for(name: &str) -> jsonschema::Validator {
    let text = std::fs::read_to_string(root().join(format!("schemas/{name}.schema.json")))
        .expect("schema exists");
    let schema: serde_json::Value = serde_json::from_str(&text).unwrap();
    jsonschema::validator_for(&schema).expect("schema compiles")
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .map(|e| e.into_path())
        .collect()
}

#[test]
fn every_example_validates_as_its_folder_says() {
    let examples = root().join("examples");
    let mut checked = 0;
    for type_dir in std::fs::read_dir(&examples).unwrap().flatten() {
        let name = type_dir.file_name().to_string_lossy().to_string();
        let v = validator_for(&name);
        for f in walk(&type_dir.path().join("valid")) {
            let inst: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&f).unwrap()).unwrap();
            let errors: Vec<String> = v.iter_errors(&inst).map(|e| e.to_string()).collect();
            assert!(
                errors.is_empty(),
                "{} should be valid: {errors:?}",
                f.display()
            );
            checked += 1;
        }
        for f in walk(&type_dir.path().join("invalid")) {
            let inst: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&f).unwrap()).unwrap();
            assert!(!v.is_valid(&inst), "{} should be invalid", f.display());
            checked += 1;
        }
    }
    assert!(checked >= 2, "no examples found");
}
