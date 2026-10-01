//! Export the single registry; contains no credentials or runtime state.
fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&cmsg::door::surface::bundle()).unwrap()
    );
}
