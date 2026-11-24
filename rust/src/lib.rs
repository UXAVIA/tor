// SPDX-FileCopyrightText: 2024 Foundation Devices Inc.
//
// SPDX-License-Identifier: MIT

// A stop can make Arti panic on a Tokio worker (see the profiles in
// Cargo.toml). That is harmless only while panics unwind.
#[cfg(not(panic = "unwind"))]
compile_error!(
    "rust_lib_tor must be built with panic = \"unwind\": with \"abort\", stopping Tor can abort the app"
);

pub mod api;
mod frb_generated;
