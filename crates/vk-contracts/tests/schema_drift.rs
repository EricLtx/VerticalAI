use std::path::PathBuf;

fn schemas_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/schemas")
}

#[test]
fn committed_schemas_match_generated() {
    for (name, schema) in vk_contracts::schema_registry() {
        let path = schemas_dir().join(format!("{name}.schema.json"));
        let on_disk = std::fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!(
                "missing {} — run `cargo run -p vk-contracts --bin gen-schemas`",
                path.display()
            )
        });
        let generated = serde_json::to_string_pretty(&schema).unwrap() + "\n";
        assert_eq!(
            on_disk, generated,
            "schema drift in {name}; regenerate and commit"
        );
    }
}
