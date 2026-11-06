use rivect::providers::{Dialect, dialect_for};

#[test]
fn bedrock_ids_map_to_their_recorded_dialects() {
    assert_eq!(dialect_for("amazon-bedrock"), Some(Dialect::Converse));
    assert_eq!(dialect_for("bedrock-mantle"), Some(Dialect::Responses));
    for id in [
        "bedrock",
        "bedrock-converse",
        "mantle",
        "bedrock-runtime",
        "bedrock-anthropic",
        "google-vertex-anthropic",
        "microsoft-foundry",
    ] {
        assert_eq!(dialect_for(id), None, "{id}");
    }
}
