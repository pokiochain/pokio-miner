# pokio-miner

# Build on Ubuntu

This guide walks you through how to install Rust and compile a Pokio Miner on Ubuntu.

---

## 1. Install Required Dependencies

Make sure your system is up to date:

```
sudo apt update && sudo apt upgrade -y
```

Then install the required tools:

```
sudo apt install -y curl build-essential pkg-config libssl-dev git
```

---

## 2. Install Rust (via rustup)

Use the official installer from rust-lang:

```
curl https://sh.rustup.rs -sSf | sh
```

Select option `1` for default installation.

After installation, reload the environment:

```
source $HOME/.cargo/env
```

Verify Rust and Cargo are installed:

```
rustc --version
cargo --version
```

---

## 3. Clone this repository

```
git clone https://github.com/pokiochain/pokio-miner.git
cd pokio-miner
```

---

## 4. Build

To build a **release version** (optimized):

```
cargo build --release
```

The binary will be located in:

```
./target/release/pokiominer
```

Run it with:

```
./target/release/pokiominer --w YOUR_WALLET_ADDRESS --t THREADS
```

---

