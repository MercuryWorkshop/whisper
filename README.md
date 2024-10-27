# whisper
Wisp protocol client that exposes the Wisp connection over a TUN device.

## Subprojects
### lib
Contains the actual Wisp <-> TUN forwarding logic. Used by cli, libwhisper, and the networkmanager plugin.

### libwhisper
C bindings to the Rust library. Would be used for an android/ios client. Not implemented yet.

### networkmanager
NetworkManager VPN plugin. Coming soon.

### cli
CLI interface for the Rust library.
