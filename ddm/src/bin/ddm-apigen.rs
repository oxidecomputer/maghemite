use anyhow::anyhow;
use anyhow::Result;
use ddm::admin::api_description;
use std::fs::File;

fn main() -> Result<()> {
    let api = api_description().map_err(|e| anyhow!("{}", e))?;
    let openapi = api.openapi("DDM Admin", "v0.1.0");
    let mut out = File::create("ddm-admin.json")?;
    openapi.write(&mut out)?;
    Ok(())
}
