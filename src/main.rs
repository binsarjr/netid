use anyhow::{anyhow, Result};
use clap::Parser;
use regex::Regex;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};

const WHOIS_PORT: u16 = 43;

// TLD to country code - EXACT mappings only
fn get_tld_country() -> std::collections::HashMap<&'static str, &'static str> {
    [
        // Indonesia
        ("id", "ID"), ("co.id", "ID"), ("or.id", "ID"), ("go.id", "ID"),
        ("sch.id", "ID"), ("my.id", "ID"), ("web.id", "ID"), ("biz.id", "ID"),
        ("net.id", "ID"), ("mil.id", "ID"),
        // Singapore
        ("sg", "SG"), ("com.sg", "SG"), ("org.sg", "SG"), ("net.sg", "SG"),
        ("edu.sg", "SG"), ("gov.sg", "SG"),
        // Malaysia
        ("my", "MY"), ("com.my", "MY"), ("net.my", "MY"), ("org.my", "MY"),
        ("edu.my", "MY"), ("gov.my", "MY"),
        // United States
        ("us", "US"), ("com.us", "US"), ("net.us", "US"), ("org.us", "US"),
        // China
        ("cn", "CN"), ("com.cn", "CN"), ("net.cn", "CN"), ("org.cn", "CN"), ("gov.cn", "CN"),
        // Japan
        ("jp", "JP"), ("co.jp", "JP"), ("ne.jp", "JP"), ("or.jp", "JP"), ("ac.jp", "JP"),
        // UK
        ("uk", "GB"), ("co.uk", "GB"), ("org.uk", "GB"), ("net.uk", "GB"), ("ac.uk", "GB"),
        // Germany
        ("de", "DE"),
        // France
        ("fr", "FR"),
        // Russia
        ("ru", "RU"), ("com.ru", "RU"), ("net.ru", "RU"), ("org.ru", "RU"),
    ].iter().cloned().collect()
}

#[derive(Parser, Debug)]
#[command(name = "netid")]
#[command(version = "0.1.0")]
#[command(about = "Check country of domain or IP")]
struct Args {
    /// Domain or IP address to check
    input: String,

    /// Target country code(s) to check against (e.g., id,sg,my)
    /// If not specified, defaults to ID (Indonesia)
    #[arg(short, long, value_delimiter = ',', default_value = "ID")]
    target: Vec<String>,
}

fn main() {
    let args = Args::parse();

    let targets: HashSet<String> = args.target.iter()
        .map(|s| s.to_uppercase())
        .collect();

    match check_country(&args.input, &targets) {
        Ok(Some(country)) => {
            if targets.contains(&country) {
                println!("true");
                std::process::exit(0);
            } else {
                println!("false");
                std::process::exit(1);
            }
        }
        Ok(None) => {
            println!("false");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(2);
        }
    }
}

fn check_country(input: &str, _targets: &HashSet<String>) -> Result<Option<String>> {
    let input = input.trim();

    // Check if input is an IP address
    if input.parse::<IpAddr>().is_ok() {
        // Try WHOIS lookup for IP first (fast, no external API)
        if let Ok(country) = whois_ip_lookup(input) {
            return Ok(Some(country));
        }
        return Ok(None);  // Don't guess, return unknown
    }

    // Otherwise treat as domain
    let domain = input.to_lowercase();

    // Quick check: TLD mapping (instant, exact)
    if let Some(&country) = get_tld_country().get(domain.split('.').last().unwrap_or("")) {
        return Ok(Some(country.to_string()));
    }

    // Do WHOIS lookup for domain
    domain_whois_lookup(&domain)
}

// WHOIS IP lookup - query appropriate RIR
fn whois_ip_lookup(ip: &str) -> Result<String> {
    // Determine which RIR based on IP first octet
    let first_octet: u8 = ip.split('.').next()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);

    let server = if first_octet >= 1 && first_octet <= 59 {
        // APNIC (Asia-Pacific)
        "whois.apnic.net"
    } else if first_octet >= 60 && first_octet <= 89 {
        // RIPE (Europe, Middle East)
        "whois.ripe.net"
    } else if first_octet >= 90 && first_octet <= 126 {
        // ARIN (North America)
        "whois.arin.net"
    } else if first_octet >= 128 && first_octet <= 191 {
        // APNIC or RIPE
        "whois.apnic.net"
    } else {
        // ARIN
        "whois.arin.net"
    };

    query_whois(ip, server)
}

fn query_whois(input: &str, server: &str) -> Result<String> {
    // Resolve hostname
    let addr = resolve_hostname(server)?;
    let socket_addr = SocketAddr::new(addr, WHOIS_PORT);

    let mut stream = TcpStream::connect_timeout(&socket_addr, std::time::Duration::from_secs(10))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;

    // For ARIN, use "n -" prefix
    let request = if server == "whois.arin.net" {
        format!("n -{}\r\n", input)
    } else {
        format!("{}\r\n", input)
    };

    stream.write_all(request.as_bytes())?;

    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];

    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buffer[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => return Err(anyhow!("Read error: {}", e)),
        }
    }

    let response_str = String::from_utf8_lossy(&response);
    extract_country(&response_str)
}

fn extract_country(whois_data: &str) -> Result<String> {
    // Look for country field
    let country_regex = Regex::new(r"(?i)country:\s*(\w{2})")?;

    if let Some(caps) = country_regex.captures(whois_data) {
        if let Some(country) = caps.get(1) {
            return Ok(country.as_str().to_uppercase());
        }
    }

    // Check for country name mentions
    let country_names = [
        ("INDONESIA", "ID"),
        ("SINGAPORE", "SG"),
        ("MALAYSIA", "MY"),
        ("JAPAN", "JP"),
        ("CHINA", "CN"),
        ("UNITED STATES", "US"),
        ("AMERICA", "US"),
        ("GERMANY", "DE"),
        ("FRANCE", "FR"),
        ("RUSSIA", "RU"),
        ("AUSTRALIA", "AU"),
        ("UNITED KINGDOM", "GB"),
    ];

    let lower = whois_data.to_lowercase();
    for (name, code) in &country_names {
        if lower.contains(&name.to_lowercase()) {
            return Ok(code.to_string());
        }
    }

    Err(anyhow!("Could not determine country"))
}

fn domain_whois_lookup(domain: &str) -> Result<Option<String>> {
    // Query IANA whois server
    let result = query_whois(domain, "whois.iana.org");

    match result {
        Ok(country) => Ok(Some(country)),
        Err(_) => Ok(None),
    }
}

fn resolve_hostname(hostname: &str) -> Result<IpAddr> {
    use std::net::ToSocketAddrs;

    // Try to resolve using std
    let addr = (hostname, WHOIS_PORT).to_socket_addrs()?;
    Ok(addr.map(|a| a.ip()).next().unwrap_or_else(|| "0.0.0.0".parse().unwrap()))
}
