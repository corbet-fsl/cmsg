//! Project test dependency: generate Web bindings without installing a CLI.
fn main() -> anyhow::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let input = args.next().ok_or_else(|| anyhow::anyhow!("missing Wasm input"))?;
    let output = args.next().ok_or_else(|| anyhow::anyhow!("missing output directory"))?;
    let name = args.next().ok_or_else(|| anyhow::anyhow!("missing module name"))?;
    let name = name.to_str().ok_or_else(|| anyhow::anyhow!("invalid module name"))?;
    anyhow::ensure!(args.next().is_none(), "unexpected arguments");
    wasm_bindgen_cli_support::Bindgen::new()
        .input_path(std::path::PathBuf::from(input))
        .web(true)?
        .omit_default_module_path(false)
        .out_name(name)
        .typescript(true)
        .generate(std::path::PathBuf::from(output))?;
    Ok(())
}
