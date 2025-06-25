may need to static compile crt
cargo rustc --release --bin byont -- -C target-feature=+crt-static