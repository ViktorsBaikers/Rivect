// ----- shared catalogue vocabulary (DEC-007) ------------------------------------

/// The shared catalogue record carries the maximum-output carrier:
/// a stated cap survives the value surface unchanged, an unstated one
/// stays `None`, and `providers.rs` re-exports this same record and
/// its price rather than defining a second copy.
#[test]
fn catalogue_vocabulary_carries_max_output_tokens() {
    use rivect::providers::{CatalogModel as SharedCatalogModel, ModelPrice as SharedModelPrice};

    let entry: SharedCatalogModel = CatalogModel {
        id: "carrier-model".to_string(),
        context_window: Some(262144),
        max_output_tokens: Some(65536),
        price: ModelPrice::Usd {
            input_per_1m: 0.15,
            output_per_1m: 0.6,
        },
        ..CatalogModel::default()
    };
    assert_eq!(
        entry.max_output_tokens,
        Some(65536),
        "the stated maximum-output cap survives the record"
    );
    assert_eq!(
        CatalogModel::default().max_output_tokens,
        None,
        "an unstated maximum-output cap is the default"
    );
    let price: SharedModelPrice = entry.price;
    assert_eq!(
        price,
        ModelPrice::Usd {
            input_per_1m: 0.15,
            output_per_1m: 0.6,
        },
        "the re-exported price names the same record"
    );
}

/// The recorded seed floor keeps every entry byte-for-byte: an empty
/// listing still answers the built-in roster with the same id, vision,
/// effort ladder, context window and price, and the new maximum-output
/// carrier stays `None` because no built-in row states a cap.
#[tokio::test]
async fn existing_catalogue_seeds_keep_their_entries() {
    let server = MockServer::start().await;
    mount_models(&server, vec![]).await;
    let config = Config::parse_validated(&deepseek_config(&server_uri_v1(&server))).expect("valid");
    let (provider, _store) = enrolled_deepseek_provider(&config);
    let (provider, catalog) = catalog_on_thread(provider);
    let models = catalog.expect("the recorded seed answers an empty listing");
    drop_blocking(provider);

    let expected: Vec<CatalogModel> = DEEPSEEK_BUILTIN_IDS
        .iter()
        .map(|id| deepseek_expected_model(id))
        .collect();
    assert_eq!(
        models, expected,
        "the seed keeps every recorded id, vision, effort, context and price"
    );
}
