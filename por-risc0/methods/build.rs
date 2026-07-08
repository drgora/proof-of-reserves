use risc0_build::{DockerOptionsBuilder, GuestOptionsBuilder};
use std::collections::HashMap;

fn main() {
    // Re-run this script when the Docker flag flips, so toggling RISC0_USE_DOCKER actually
    // rebuilds the guest. Without this, cargo reuses the cached build-script output and a
    // `RISC0_USE_DOCKER=1` build silently keeps the previous (local, wrong-image_id) ELF.
    println!("cargo:rerun-if-env-changed=RISC0_USE_DOCKER");

    // Reproducible guest build. When RISC0_USE_DOCKER=1, compile the guest inside the
    // pinned `risczero/risc0-guest-builder` container (risc0-build 3.0.5 default tag
    // r0.1.88.0) against the guest's committed Cargo.lock (`cargo build --locked`). This
    // makes POR_GUEST_ID deterministic and auditable -- it is the image_id we register as
    // the HL marketplace vkHash (risc0 vk_hash is the identity function), and the one the
    // prover proves against, so a reproducibly-built prover matches the registered vk.
    //
    // Without the flag, fall back to the local toolchain for fast dev iteration. That
    // image_id will generally DIFFER from the Docker one and will NOT match the registered
    // vk -- only build/prove for the marketplace with RISC0_USE_DOCKER=1.
    if std::env::var_os("RISC0_USE_DOCKER").is_some() {
        let docker = DockerOptionsBuilder::default()
            .root_dir("guest") // build context = methods/guest (self-contained: own [workspace] + Cargo.lock)
            // Pin the guest-builder container explicitly. risc0-build 3.0.5 defaults to
            // r0.1.88.0 (rustc 1.88), but the guest's Cargo.lock pins deps (ruint 1.18,
            // enum-ordinalize 4.4) that require rustc >= 1.90. r0.1.91.1 ships rustc 1.91.1
            // -- it matches the local rzup rust toolchain, so the reproducible image_id lines
            // up with a local build. Bump this in lockstep with `rzup show` / the guest lock.
            .docker_container_tag("r0.1.91.1")
            .build()
            .unwrap();
        let opts = GuestOptionsBuilder::default().use_docker(docker).build().unwrap();
        let mut map = HashMap::new();
        map.insert("por_guest", opts); // key = guest package name (Cargo.toml `name`)
        risc0_build::embed_methods_with_options(map);
    } else {
        risc0_build::embed_methods();
    }
}
