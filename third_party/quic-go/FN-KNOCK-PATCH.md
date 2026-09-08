# quic-go v0.62.0 local patch

Source: https://github.com/quic-go/quic-go/tree/v0.62.0
License: MIT (see LICENSE).

Upstream always advertises Extended CONNECT. fn-knock v1 does not implement
HTTP/3 WebSockets. The sole production change adds
`http3.Server.DisableExtendedConnect`, default false, to omit this setting.
The gateway sets it true. cmd/server tests verify the wire-level SETTINGS.
Remove this fork when upstream exposes an equivalent option. Track upstream
security fixes against v0.62.0 when maintaining this source.
