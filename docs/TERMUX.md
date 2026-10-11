# Using in Termux on rooted devices
## Build Yggdrasil-ng for Termux
***Please note! To run Yggdrasil-ng in Termux on a rooted device, do not build for Android. Build specifically for Linux!***

The `aarch64-unknown-linux-musl` target, or another `*-unknown-linux-musl` target if your system has a different architecture, will work perfectly for you.

```bash
YGGDRASIL_CONFIG_DIR=/data/data/com.termux/files/usr/etc/yggdrasil \
YGGDRASIL_ROUTES_CACHE_DIR=/data/data/com.termux/files/usr/var/cache/yggdrasil \
cargo build --release --target aarch64-unknown-linux-musl
```
If it fails to build on Arch Linux-like distros, install `zig`, `cargo-zigbuild`.
```bash
yay -Sy zig
cargo install cargo-zigbuild
```
And build it as follows:
```bash
YGGDRASIL_CONFIG_DIR=/data/data/com.termux/files/usr/etc/yggdrasil \
YGGDRASIL_ROUTES_CACHE_DIR=/data/data/com.termux/files/usr/var/cache/yggdrasil \
cargo zigbuild --release --target aarch64-unknown-linux-musl
```