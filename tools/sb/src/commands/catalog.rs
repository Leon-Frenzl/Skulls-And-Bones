use sb_core::rpc::RPC_METHOD_SUITE_CATALOG;
use sb_core::{daemon_client::DaemonClient, SuiteProduct};

pub fn handle_catalog(json_output: bool) -> Result<(), String> {
    let products: Vec<SuiteProduct> = match DaemonClient::try_connect_default()? {
        Some(client) => {
            let response = client.call(RPC_METHOD_SUITE_CATALOG, serde_json::json!({}))?;
            serde_json::from_value(response).map_err(|error| {
                format!("Daemon lieferte ein ungültiges Produktinventar: {error}")
            })?
        }
        None => sb_core::catalog::products()?.to_vec(),
    };

    if json_output {
        let output = serde_json::to_string_pretty(&products).map_err(|error| {
            format!("Produktinventar konnte nicht serialisiert werden: {error}")
        })?;
        println!("{output}");
        return Ok(());
    }

    println!(
        "{:<12} {:<28} {:<12} {:<38} VERSION",
        "ID", "PRODUKT", "TYP", "REIFEGRAD"
    );
    println!("{}", "-".repeat(110));
    for product in products {
        println!(
            "{:<12} {:<28} {:<12} {:<38} {}",
            product.id,
            product.title,
            product.product_kind.label(),
            product.maturity.label(),
            product.package_version
        );
    }
    Ok(())
}
