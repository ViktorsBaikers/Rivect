//! Sandbox mechanism linking for the confined helper: `sandbox_init` ships
//! as the SDK's `usr/lib/libsandbox` library (no macOS framework), so the
//! helper links it directly.

fn main() {
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-lib=sandbox");
    }
}
