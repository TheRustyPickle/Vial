<div align="center"><h1>Vial</h1></div>
<div align="center">
<a href="https://wakatime.com/@RustyPickle"><img src="https://wakatime.com/badge/github/TheRustyPickle/Vial.svg" alt="wakatime"></a>
</div>

Vial is a small Rust project for end-to-end encrypted secret sharing.

Secrets are encrypted on the client, sent to a server as ciphertext, and decrypted only by the recipient.
The server never knows the decryption key or the contents of a secret.

The primary tool is a CLI. A web UI is provided as an optional way to view secrets.

## What It Does

- Create encrypted secrets (text or files) using a password or a random key
- Upload encrypted payloads to a server
- Fetch and decrypt secrets locally
- Enforce expiration and view limits on the server
- Self-hostable server or reusable server library

## Workspace Members

| Crate      | Description                                                               |
|------------|------------                                                               |
| [vial-cli](cli)        | CLI binary (secret creation & consumption)                    |
| [vial-core](cli)       | Cryptography primitives (encryption / decryption)             |
| [vial-shared](shared)  | Shared request / response types                               |
| [vial-srv](srv-lib)    | Framework-agnostic server logic/library (DB, rules, limits)   |
| [vial-server](server)  | Actix-web server binary using srv-lib                         |

## Installation

**1. Run from Source Code:**

- Clone the repository `git clone https://github.com/TheRustyPickle/Vial`
- To run the CLI with Cargo `cargo run --release --bin vial`
- To run the server with Cargo `cargo run --release --bin vial-server`

**2. Run the latest Release:**

- Download the latest executable from [Releases](https://github.com/TheRustyPickle/Vial/releases/latest).
- Unzip the executable and run via terminal

**3. Install using Cargo:**

Coming soon

## Web UI

[A web UI is available](https://rustypickle.onrender.com/) with [source code](https://github.com/TheRustyPickle/My-Site/blob/main/app/src/secrets.rs) and is used as the default URL in the CLI. The site uses the same `srv-lib` and can only perform decryption on the client.

## Project Status & Disclaimer

This project:

- Has not been security audited
- Comes with no guarantees or warranties

Use at your own risk. Do not rely on it for high-value or high-risk secrets.

## License

[MIT License](LICENSE).
