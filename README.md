# Project X

[Project X](https://github.com/XTLS) originates from XTLS protocol, providing a set of network tools such as [Xray-core](https://github.com/XTLS/Xray-core) and [REALITY](https://github.com/XTLS/REALITY).

[README](https://github.com/XTLS/Xray-core#readme) is open, so feel free to submit your project [here](https://github.com/XTLS/Xray-core/pulls).

## Sponsors

[![Remnawave](https://github.com/user-attachments/assets/a22d34ae-01ee-441c-843a-85356748ed1e)](https://docs.rw)

[![Happ](https://github.com/user-attachments/assets/14055dab-e8bb-48bd-89e8-962709e4098e)](https://happ.su)

[![BlancVPN](https://github.com/user-attachments/assets/9145ea7d-5da3-446e-8143-710dba4292c3)](https://blanc.link/VMTSDqW)

[**Sponsor Xray-core**](https://github.com/XTLS/Xray-core/issues/3668)

## Donation & NFTs

### [Collect a Project X NFT to support the development of Project X!](https://opensea.io/item/ethereum/0x5ee362866001613093361eb8569d59c4141b76d1/1)

[<img alt="Project X NFT" width="150px" src="https://raw2.seadn.io/ethereum/0x5ee362866001613093361eb8569d59c4141b76d1/7fa9ce900fb39b44226348db330e32/8b7fa9ce900fb39b44226348db330e32.svg" />](https://opensea.io/item/ethereum/0x5ee362866001613093361eb8569d59c4141b76d1/1)

- **TRX(Tron)/USDT/USDC: `TNrDh5VSfwd4RPrwsohr6poyNTfFefNYan`**
- **TON: `UQApeV-u2gm43aC1uP76xAC1m6vCylstaN1gpfBmre_5IyTH`**
- **BTC: `1JpqcziZZuqv3QQJhZGNGBVdCBrGgkL6cT`**
- **XMR: `4ABHQZ3yJZkBnLoqiKvb3f8eqUnX4iMPb6wdant5ZLGQELctcerceSGEfJnoCk6nnyRZm73wrwSgvZ2WmjYLng6R7sR67nq`**
- **SOL/USDT/USDC: `3x5NuXHzB5APG6vRinPZcsUv5ukWUY1tBGRSJiEJWtZa`**
- **ETH/USDT/USDC: `0xDc3Fe44F0f25D13CACb1C4896CD0D321df3146Ee`**
- **Project X NFT: https://opensea.io/item/ethereum/0x5ee362866001613093361eb8569d59c4141b76d1/1**
- **VLESS NFT: https://opensea.io/collection/vless**
- **REALITY NFT: https://opensea.io/item/ethereum/0x5ee362866001613093361eb8569d59c4141b76d1/2**
- **Related links: [VLESS Post-Quantum Encryption](https://github.com/XTLS/Xray-core/pull/5067), [XHTTP: Beyond REALITY](https://github.com/XTLS/Xray-core/discussions/4113), [Announcement of NFTs by Project X](https://github.com/XTLS/Xray-core/discussions/3633)**

## License

[Mozilla Public License Version 2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE)

## Documentation

[Project X Official Website](https://xtls.github.io)

### Transport buffer contracts

- Trojan UDP framing accepts payloads up to 8192 bytes for IPv4, IPv6, and domain destinations; framing overhead does not reduce that payload limit.
- Native Shadowsocks 2022 UDP decoding consumes and may modify its input. The returned payload aliases that input: retain its buffer until the downstream consumer releases it, and copy ciphertext before decoding when it must be preserved.
- Native Shadowsocks 2022 streams retain the 65535-byte wire chunk limit. Returned consumer buffers remain at most 8192 bytes for compatibility with chained Vision writers; normal chunks decrypt directly into owned buffers, while larger chunks reuse scratch and split into regular buffers.
- Stream payloads at the 8K AEAD-tag boundary use reusable ciphertext scratch and decrypt directly into a separately owned regular 8K buffer, so queued plaintext does not require a larger pool bucket.
- The shared buffered stream adapter preserves bytes returned alongside EOF or another source error. Deferred errors remain observable after draining those bytes, including when switching between byte reads, bounded reads, multi-buffer reads, and `WriteTo`.
- TLS and WebSocket multi-buffer writes consume their input buffers, including on write errors; callers must not reuse the consumed payloads or rely on retained slice entries. Singleton writes avoid one temporary pointer-slice allocation while preserving TLS stream bytes and WebSocket binary-message boundaries.
- Authenticated stream writers consume their input and seal singleton payloads directly into separately owned output, splitting oversized payloads at the existing frame limit without temporary plaintext copies or scratch allocations. Oversized singleton input is released before forwarding the complete ciphertext batch. Chunk framing, authentication, nonce progression, padding, and error handling are unchanged; multi-buffer inputs retain the existing chunk-packing path.
- TCP stream-vector adapters consume their input on success or error, reuse the vector header and storage between writes, and count actual bytes written, including partial-error returns. Progress follows the remaining vectors rather than an int32 aggregate, so supported multi-buffer writes totaling 2 GiB or more are not silently skipped. Existing packet and non-syscall writer routing is unchanged.

### Connection lifecycle and WireGuard setup

- Removing an outbound through the handler API closes its existing connections, including mux and XUDP workers. Removal also releases the outbound's owned resources; it is not a graceful drain.
- Removing an inbound user revokes authentication and cancels that user's existing sessions. Cancellation belongs to the inbound's user instance: independently configured users on other inbounds remain active, and Hysteria's derived routing identities share their original user's lifetime.
- UDP worker cleanup removes only the connection that still owns its map entry, so a finishing old processor cannot erase a replacement connection.
- A WireGuard client retains the device that owns its TUN when setup fails. Later initialization attempts reuse that device; successful peer configuration is not reapplied merely because bringing the device up failed. Bind setup retains routing values but is canceled by the handler's lifetime rather than the first request, so a canceled failed request does not poison later setup attempts.
- Direct WireGuard endpoint sockets use Xray DNS. FinalMask and dialer-proxy paths retain the original domain. Peer and socket resolution remain independent and may select different addresses from a multi-address DNS answer.
- Direct WireGuard UDP sockets retain batched receives and sends on Linux/Android. Where Linux UDP GSO is supported, eligible nonempty datagram runs share a scatter-gather `UDP_SEGMENT` message within the existing send batch, without coalescing copies or payload mutations beyond the existing reserved-byte handling. Empty and ineligible datagrams remain separate batched messages. Unsupported-offload or path-MTU errors disable GSO for that socket and retry only unsent datagrams through ordinary batching; completed datagrams are never resent and byte counters count only successful sends. Wrapped sockets and other platforms retain their existing paths.
- Singleton WireGuard sends bypass GSO grouping. Pooled message cleanup resets only the slots touched by a send or receive, retaining the high-water mark across multi-chunk sends so no packet-buffer references or ancillary metadata survive reuse. Kernel send errors remain errors rather than panics, including raw negative batch-completion counts after an already transmitted prefix.

## Telegram

[Project X](https://t.me/projectXray)

[Project X Channel](https://t.me/projectXtls)

[Project VLESS](https://t.me/projectVless) (Русский)

[Project XHTTP](https://t.me/projectXhttp) (Persian)

## Installation

- Linux Script
  - [XTLS/Xray-install](https://github.com/XTLS/Xray-install) (**Official**)
  - [tempest](https://github.com/team-cloudchaser/tempest) (supports [`systemd`](https://systemd.io) and [OpenRC](https://github.com/OpenRC/openrc); Linux-only)
- Docker
  - [ghcr.io/xtls/xray-core](https://ghcr.io/xtls/xray-core) (**Official**)
  - [teddysun/xray](https://hub.docker.com/r/teddysun/xray)
  - [wulabing/xray_docker](https://github.com/wulabing/xray_docker)
- Web Panel
  - [Remnawave](https://github.com/remnawave/panel)
  - [3X-UI](https://github.com/MHSanaei/3x-ui)
  - [PasarGuard](https://github.com/PasarGuard/panel)
  - [Xray-UI](https://github.com/qist/xray-ui)
  - [X-Panel](https://github.com/xeefei/X-Panel)
  - [Marzban](https://github.com/Gozargah/Marzban)
  - [Hiddify](https://github.com/hiddify/Hiddify-Manager)
  - [TX-UI](https://github.com/AghayeCoder/tx-ui)
  - [CELERITY](https://github.com/ClickDevTech/CELERITY-panel)
- One Click
  - [Xray-REALITY](https://github.com/zxcvos/Xray-script), [xray-reality](https://github.com/sajjaddg/xray-reality), [reality-ezpz](https://github.com/aleskxyz/reality-ezpz)
  - [Xray_bash_onekey](https://github.com/hello-yunshu/Xray_bash_onekey), [XTool](https://github.com/LordPenguin666/XTool), [VPainLess](https://github.com/vpainless/vpainless)
  - [v2ray-agent](https://github.com/mack-a/v2ray-agent), [Xray_onekey](https://github.com/wulabing/Xray_onekey), [ProxySU](https://github.com/proxysu/ProxySU)
- Magisk
  - [Magic_V2Ray](https://github.com/vincentng295/Magic_V2Ray)
  - [Xray_For_Magisk](https://github.com/E7KMbb/Xray_For_Magisk)
- Homebrew
  - `brew install xray`

## Usage

- Example
  - [VLESS-XTLS-uTLS-REALITY](https://github.com/XTLS/REALITY#readme)
  - [VLESS-TCP-XTLS-Vision](https://github.com/XTLS/Xray-examples/tree/main/VLESS-TCP-XTLS-Vision)
  - [All-in-One-fallbacks-Nginx](https://github.com/XTLS/Xray-examples/tree/main/All-in-One-fallbacks-Nginx)
- Xray-examples
  - [XTLS/Xray-examples](https://github.com/XTLS/Xray-examples)
  - [chika0801/Xray-examples](https://github.com/chika0801/Xray-examples)
  - [lxhao61/integrated-examples](https://github.com/lxhao61/integrated-examples)
- Tutorial
  - [XTLS Vision](https://github.com/chika0801/Xray-install)
  - [REALITY (English)](https://cscot.pages.dev/2023/03/02/Xray-REALITY-tutorial/)
  - [XTLS-Iran-Reality (English)](https://github.com/SasukeFreestyle/XTLS-Iran-Reality)
  - [Xray REALITY with 'steal oneself' (English)](https://computerscot.github.io/vless-xtls-utls-reality-steal-oneself.html)
  - [Xray with WireGuard inbound (English)](https://g800.pages.dev/wireguard)

## GUI Clients

- OpenWrt
  - [PassWall](https://github.com/Openwrt-Passwall/openwrt-passwall), [PassWall 2](https://github.com/Openwrt-Passwall/openwrt-passwall2)
  - [ShadowSocksR Plus+](https://github.com/fw876/helloworld)
  - [luci-app-xray](https://github.com/yichya/luci-app-xray) ([openwrt-xray](https://github.com/yichya/openwrt-xray))
- Asuswrt-Merlin
  - [XRAYUI](https://github.com/DanielLavrushin/asuswrt-merlin-xrayui)
  - [fancyss](https://github.com/hq450/fancyss)
- Windows
  - [v2rayN](https://github.com/2dust/v2rayN)
  - [Furious](https://github.com/LorenEteval/Furious)
  - [Invisible Man - Xray](https://github.com/InvisibleManVPN/InvisibleMan-XRayClient)
  - [AnyPortal](https://github.com/AnyPortal/AnyPortal)
  - [GenyConnect](https://github.com/genyleap/GenyConnect)
  - [OneXray](https://github.com/OneXray/OneXray)
  - [XrayUI-dev](https://github.com/PhoenixNil/XrayUI-dev)
- Android
  - [v2rayNG](https://github.com/2dust/v2rayNG)
  - [X-flutter](https://github.com/XTLS/X-flutter)
  - [SaeedDev94/Xray](https://github.com/SaeedDev94/Xray)
  - [SimpleXray](https://github.com/lhear/SimpleXray)
  - [XrayFA](https://github.com/Q7DF1/XrayFA)
  - [AnyPortal](https://github.com/AnyPortal/AnyPortal)
  - [OneXray](https://github.com/OneXray/OneXray)
  - [AsteriskNG](https://github.com/Asterisk4Magisk/AsteriskNG)
- iOS & macOS arm64 & tvOS
  - [Happ](https://apps.apple.com/app/happ-proxy-utility/id6504287215) | [Happ RU](https://apps.apple.com/ru/app/happ-proxy-utility-plus/id6746188973) | [Happ tvOS](https://apps.apple.com/us/app/happ-proxy-utility-for-tv/id6748297274)
  - [Streisand](https://apps.apple.com/app/streisand/id6450534064)
  - [OneXray](https://github.com/OneXray/OneXray)
  - [INCY](https://apps.apple.com/en/app/incy/id6756943388)
- macOS arm64 & x64
  - [Happ](https://apps.apple.com/app/happ-proxy-utility/id6504287215) | [Happ RU](https://apps.apple.com/ru/app/happ-proxy-utility-plus/id6746188973)
  - [V2rayU](https://github.com/yanue/V2rayU)
  - [V2RayXS](https://github.com/tzmax/V2RayXS)
  - [Furious](https://github.com/LorenEteval/Furious)
  - [OneXray](https://github.com/OneXray/OneXray)
  - [GoXRay](https://github.com/goxray/desktop)
  - [AnyPortal](https://github.com/AnyPortal/AnyPortal)
  - [v2rayN](https://github.com/2dust/v2rayN)
  - [GenyConnect](https://github.com/genyleap/GenyConnect)
  - [INCY](https://apps.apple.com/en/app/incy/id6756943388)
- Linux
  - [v2rayA](https://github.com/v2rayA/v2rayA)
  - [Furious](https://github.com/LorenEteval/Furious)
  - [GorzRay](https://github.com/ketetefid/GorzRay)
  - [GoXRay](https://github.com/goxray/desktop)
  - [AnyPortal](https://github.com/AnyPortal/AnyPortal)
  - [v2rayN](https://github.com/2dust/v2rayN)
  - [GenyConnect](https://github.com/genyleap/GenyConnect)
  - [OneXray](https://github.com/OneXray/OneXray)
- HarmonyOS
  - [Hey](https://github.com/popsiclelmlm/Hey)

## Others that support VLESS, XTLS, REALITY, XUDP, PLUX...

- iOS & macOS arm64 & tvOS
  - [Anywhere](https://github.com/NodePassProject/Anywhere)
  - [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118)
  - [Loon](https://apps.apple.com/us/app/loon/id1373567447)
  - [Egern](https://apps.apple.com/us/app/egern/id1616105820)
  - [Quantumult X](https://apps.apple.com/us/app/quantumult-x/id1443988620)
- Xray Tools
  - [xray-knife](https://github.com/lilendian0x00/xray-knife)
  - [xray-checker](https://github.com/kutovoys/xray-checker)
- Xray Wrapper
  - [XTLS/libXray](https://github.com/XTLS/libXray)
  - [xtls-sdk](https://github.com/remnawave/xtls-sdk)
  - [xtlsapi](https://github.com/hiddify/xtlsapi)
  - [AndroidLibXrayLite](https://github.com/2dust/AndroidLibXrayLite)
  - [flutter_vless](https://github.com/XIIIFOX/flutter_vless)
  - [Xray-core-python](https://github.com/LorenEteval/Xray-core-python)
  - [xray-api](https://github.com/XVGuardian/xray-api)
- [XrayR](https://github.com/XrayR-project/XrayR)
  - [XrayR-release](https://github.com/XrayR-project/XrayR-release)
  - [XrayR-V2Board](https://github.com/missuo/XrayR-V2Board)
- Cores
  - [Amnezia VPN](https://github.com/amnezia-vpn)
  - [mihomo](https://github.com/MetaCubeX/mihomo)
  - [sing-box](https://github.com/SagerNet/sing-box)

## Contributing

[Code of Conduct](https://github.com/XTLS/Xray-core/blob/main/CODE_OF_CONDUCT.md)

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/XTLS/Xray-core)

## Credits

- [Xray-core v1.0.0](https://github.com/XTLS/Xray-core/releases/tag/v1.0.0) was forked from [v2fly-core 9a03cc5](https://github.com/v2fly/v2ray-core/commit/9a03cc5c98d04cc28320fcee26dbc236b3291256), and we have made & accumulated a huge number of enhancements over time, check [the release notes for each version](https://github.com/XTLS/Xray-core/releases).
- For third-party projects used in [Xray-core](https://github.com/XTLS/Xray-core), check your local or [the latest go.mod](https://github.com/XTLS/Xray-core/blob/main/go.mod).

### Bundled Third-Party Components Redistribution

**Certain optional features dynamically load third-party components. These optional components are separate works distributed under their own licenses, and are bundled into the ZIP package for ease of use. Users may replace these components under the licenses from these components.**

These components include:

#### Wintun

This distribution contains unmodified official precompiled and pre-signed Wintun binaries.

- Project: Wintun
- Copyright: Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
- Redistribution License: Prebuilt Binaries License (PBL) bundled with official precompiled and pre-signed binaries from wintun.net
- Component(s): wintun.dll
- Source: https://www.wintun.net/
- Included in:
  - Windows x86 (windows-32, win7-32)
  - Windows x86-64 (windows-64, win7-64)
  - Windows AArch64 (windows-arm64)
- Notes: Wintun is an optional runtime-loaded component only used for TUN inbound functionality on supported Windows platforms.

## One-line Compilation

### Windows (PowerShell)

```powershell
$env:CGO_ENABLED=0
go build -o xray.exe -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

### Linux / macOS

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

### Reproducible Releases

Make sure that you are using the same Go version, and remember to set the git commit id (7 bytes):

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -gcflags="all=-l=4" -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid=" -v ./main
```

For Android:

```bash
GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC=/path/to/aarch64-linux-android24-clang go build -o xray -trimpath -buildvcs=false -gcflags="all=-l=4" -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid= -checklinkname=0" -v ./main
GOOS=android GOARCH=amd64 CGO_ENABLED=1 CC=/path/to/x86_64-linux-android24-clang go build -o xray -trimpath -buildvcs=false -gcflags="all=-l=4" -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid= -checklinkname=0" -v ./main
```

If you are compiling a 32-bit MIPS/MIPSLE target, use this command instead:

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -gcflags="-l=4" -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid=" -v ./main
```

## Stargazers over time

[![Stargazers over time](https://starchart.cc/XTLS/Xray-core.svg)](https://starchart.cc/XTLS/Xray-core)
