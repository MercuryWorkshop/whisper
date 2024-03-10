# Whisper

Whisper is an implementation of the [Wisp protocol](https://github.com/MercuryWorkshop/wisp-protocol) over a pty. It is designed to be used as a network bridge between a virtual machine and a host machine over a serial connection.

## Installation

```bash
cargo install whisper-tun
```

## Usage

```bash
whisper pty=/dev/ttyUSB0 iface=wisp0
```

## License

Whisper is licensed under the [GNU GPL-3.0-or-later license](https://www.gnu.org/licenses/gpl-3.0.html).

## Contributing

Contributions are welcome! Please write tests and make sure they pass before submitting a pull request.
