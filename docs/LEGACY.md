
# How to use Yggdrasil-ng on outdated operating systems

## Build for legacy hardware running on ancient Linux distributions

It’s not difficult to build Yggdrasil-ng for an older Linux system. However, keep in mind that Yggdrasil-ng cannot run on kernels older than 3.2. In addition, IPv6 multicast may not work properly on kernels older than 3.16. On older hardware, you'll need at least a system no older than Debian 5, Ubuntu 8.04, Slackware 12.1, Fedora 8, ALT Linux 4.1, or Mandriva 2008.0, since you can install kernel 3.2 on them even without compiling it. Why would you need this? Probably only if you’re a geek and are using an old distribution on very slow, outdated hardware from the mid-2000s or on a netbook from the late 2000s or early 2010s, where even [yggdrasil-go](https://github.com/yggdrasil-network/yggdrasil-go) runs sluggishly.
```bash
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target i686-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```
If you need to compile for an old, rooted Android device, follow the link for the [Termux build](TERMUX.md).
## Build for Ubuntu 14.04, Debian 8, Slackware 14.1

As well as building for `musl`, to support any Linux system with a kernel version 3.2 or newer, you can build a `glibc` binary that supports systems from Ubuntu 14.04, Debian 9, Slackware 14.1, RHEL 7.0, Alt Linux P7 and other systems with `glibc >= 2.17`. This binary will also work well and fast enough in all modern Linux distributions.

You will need `zig` and `cargo zigbuild`. Don’t forget to install them
```bash
yay -Sy zig
cargo install cargo-zigbuild
```
Right, now you’re ready to build
```bash
cargo zigbuild --target x86_64-unknown-linux-gnu.2.17 --release
cargo zigbuild --target i686-unknown-linux-gnu.2.17 --release
```

## Windows 7

Yes, you can still build Yggdrasil-ng for Windows 7 and it will even work. But there’s one limitation and one issue. 

**Limitation:** Only one `**00::/7` prefix at a time. But who has that ever stopped? After all, you can use CKR to access other prefixes – for example, you can stay on a private network whilst accessing the public `200::/7` via CKR.
Read [CKR documentation](CKR.md) and [IPv6 **00::/7 prefix-related documentation](PREFIX.md)

**Issue**: *Cluttering up the Windows registry. You’ll need a workaround to clean up the registry branch. I’ll explain this in more detail below.

### Build for Windows 7 from Arch Linux
**Important note:** A binary compiled for Windows 7 will work perfectly on newer versions, including **Windows 11**.

You will need `zig` and `cargo zigbuild`. Don’t forget to install them.
```bash
yay -Sy zig
cargo install cargo-zigbuild
```
You’ll also need to install `rust-src` and the nightly toolchain for your architecture to be able to build for Windows 7,
```bash
rustup component add rust-src
rustup toolchain install nightly-x86_64-unknown-linux-gnu
rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu
```
Right, now you’re ready to build
```bash
cargo +nightly zigbuild --release --target x86_64-win7-windows-gnu -Z build-std
cargo +nightly zigbuild --release --target i686-win7-windows-gnu -Z build-std
```

### A workaround for Windows7 registry cluttering

1. Install the latest possible [PowerShell for Windows 7](https://github.com/PowerShell/PowerShell/releases/tag/v7.2.24)

1. Create a file, for example `C:\myscripts\ygg-clean.ps1`
```powershell
# Administrator rights required
# Run as administrator!

# List of branches to check
$profilePaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged"
)

$removedCount = 0
$foundCount = 0

foreach ($basePath in $profilePaths) {
    Write-Host "Checking the branch: $basePath" -ForegroundColor Cyan

    # Retrieve all sub-sections
    $subkeys = Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue

    if (-not $subkeys) {
        Write-Host "  Subsections are not available or access is denied" -ForegroundColor DarkGray
        continue
    }

    foreach ($subkey in $subkeys) {
        try {
            # Retrieve the value of ‘Description’
            $description = Get-ItemPropertyValue -Path $subkey.PSPath -Name "Description" -ErrorAction SilentlyContinue

            if ($description -and $description -like "Ygg*") {
                $foundCount++
                $keyName = $subkey.PSChildName

                Write-Host "  Found: $keyName  Description = '$description'" -ForegroundColor Yellow

                # Deleting a sub-section
                Remove-Item -Path $subkey.PSPath -Recurse -Force
                $removedCount++
                Write-Host "    Removed: $keyName" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "  Error during processing $($subkey.PSChildName): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}
```
3. Set PowerShell Execution Policy \
\
In [PowerShell 7](https://github.com/PowerShell/PowerShell/releases/tag/v7.2.24), once as an administrator
```powershell
Set-ExecutionPolicy RemoteSigned
:: Correct answer => Y
```
4. Run this file when the system shuts down using the Local Group Policy Editor. \
\
`gpedit.msc` (run as an administrator) \
Computer Configuration => Windows Settings => Scripts (Startup/Shutdown) => Shutdown => Scripts=> Add => \
\
`Script Name` 
C:\Program Files\PowerShell\7\pwsh.exe \
`Script Parameters`
-ExecutionPolicy Bypass -File "C:\myscripts\ygg-clean.ps1"