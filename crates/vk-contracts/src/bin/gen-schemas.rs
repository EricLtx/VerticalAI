//! Regenerates contracts/schemas/*.schema.json from the Rust contract types.
use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/schemas");
    std::fs::create_dir_all(&dir).expect("create schemas dir");
    for (name, schema) in vk_contracts::schema_registry() {
        let path = dir.join(format!("{name}.schema.json"));
        let text = serde_json::to_string_pretty(&schema).unwrap() + "\n";
        std::fs::write(&path, text).expect("write schema");
        println!("wrote {}", path.display());
    }
}
