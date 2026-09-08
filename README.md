# ArasClient Core — Xray-core

Fork of [XTLS/Xray-core](https://github.com/XTLS/Xray-core) v26.9.1 used as the core engine of [ArasClient](https://github.com/ArasTey/ArasClient).

## What's added on top of upstream

| Feature | Description |
|---|---|
| **AnyTLS** | Full outbound protocol: TLS session multiplexing with padding, UDP over TCP (UoT), built from the [sing-anytls](https://github.com/anytls/sing-anytls) reference implementation |
| **AmneziaWG 3.1** | WireGuard outbound now runs on [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) **v3.1** — junk packet params `Jc / Jmin / Jmax / S1 / S2 / H1–H4` supported at device level (UAPI-correct order) |
| **`allowInsecure` restored** | Legacy `allowInsecure: true` maps to the new `insecure_skip_verify` field instead of being rejected |
| **H3/H4 headers fixed** | Cookie (H3) and transport (H4) packet headers were mislabeled/missing — all four now emitted |

## How ArasClient uses it

The [AndroidLibXrayLite](https://github.com/ArasTey/AndroidLibXrayLite) gomobile bindings compile this fork into `aras-core.aar`. AmneziaWG profiles additionally run through a **standalone awg-go tunnel** (the same architecture as the AmneziaVPN client) — see `AwgTurnOn` in the bindings.

## Consumed by

`AndroidLibXrayLite/go.mod`:
```
replace github.com/xtls/xray-core        => github.com/ArasTey/xray-core main
replace github.com/patterniha/xray-core  => github.com/ArasTey/xray-core main
```

## Protocol notes

- `anytls://` links: password auth (SHA-256 frame), session reuse, padding scheme negotiation, UDP via UDP-over-TCP
- `awg://` links and `.conf` files: junk params pass through unchanged; configs without them get AmneziaWG's standard defaults
