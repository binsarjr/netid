# netid

Network Identity Lookup - Check country origin of domain or IP address.

## Quick Start

### Using Docker (Recommended)

```bash
# Build once
docker build -t netid .

# Run
docker run --rm netid tokopedia.co.id
docker run --rm netid 8.8.8.8
docker run --rm netid google.com --target us,sg
```

### Using Pre-built Binary

Download from [GitHub Releases](https://github.com/binsarjr/netid/releases) for your platform.

### From Source

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cargo build --release

# Run
./target/release/netid tokopedia.co.id
```

## Usage

```bash
netid <input> [OPTIONS]

Arguments:
  <input>              Domain or IP address to check

Options:
  -t, --target <codes>  Target country codes (default: ID)
                         Multiple codes: --target id,sg,my
  -h, --help           Show help
  -V, --version        Show version
```

## Examples

```bash
# Check if domain is Indonesian (default target)
netid tokopedia.co.id       # true

# Check if domain is from Singapore
netid google.com --target sg  # false (US)

# Check multiple countries
netid google.com --target us,sg  # true (US)

# Check IP address
netid 8.8.8.8 --target us    # true
netid 202.0.0.0 --target id  # true

# Programmatic use (exit code)
netid tokopedia.co.id && echo "Indonesian" || echo "Not Indonesian"
```

## Exit Codes

- `0` - Input matches target country
- `1` - Input does NOT match target country
- `2` - Error (network, invalid input, etc.)

## Supported Countries

| Code | Country    |
|------|------------|
| ID   | Indonesia  |
| SG   | Singapore  |
| MY   | Malaysia   |
| US   | United States |
| CN   | China      |
| JP   | Japan      |
| GB   | United Kingdom |
| DE   | Germany    |
| FR   | France     |
| RU   | Russia     |

## How It Works

1. **TLD Check** - If domain ends with country-specific TLD (.id, .sg, .my, etc.), instant match
2. **IP Range Check** - Quick lookup against known IP ranges for each country
3. **WHOIS Lookup** - For uncertain cases, query WHOIS server to get registrant country

## License

MIT
