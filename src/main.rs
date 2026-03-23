use anyhow::{anyhow, Result};
use clap::Parser;
use regex::Regex;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::collections::HashSet;

const WHOIS_PORT: u16 = 43;

// Country code to IP ranges (simplified - major ranges only)
fn get_country_ranges() -> std::collections::HashMap<&'static str, Vec<(&'static str, &'static str)>> {
    let mut ranges = std::collections::HashMap::new();

    // Indonesia - specific ISP and provider IP ranges
    // Avoid /8 blocks that overlap with other countries
    ranges.insert("ID", vec![
        // DigitalOcean, Vultr, etc (common cloud providers in ID)
        ("159.223.0.0/16", "159.223.0.0 - 159.223.255.255"),
        // Telkom (most specific)
        ("110.138.0.0/15", "110.138.0.0 - 110.139.255.255"),
        ("114.4.0.0/16", "114.4.0.0 - 114.4.255.255"),
        ("114.56.0.0/14", "114.56.0.0 - 114.59.255.255"),
        ("116.0.0.0/12", "116.0.0.0 - 116.15.255.255"),
        ("116.66.0.0/17", "116.66.0.0 - 116.66.127.255"),
        ("116.68.0.0/17", "116.68.0.0 - 116.68.127.255"),
        ("116.197.0.0/17", "116.197.0.0 - 116.197.127.255"),
        ("116.206.0.0/15", "116.206.0.0 - 116.207.255.255"),
        ("116.254.0.0/18", "116.254.0.0 - 116.254.63.255"),
        ("117.102.0.0/17", "117.102.0.0 - 117.102.127.255"),
        ("117.102.128.0/17", "117.102.128.0 - 117.102.255.255"),
        ("118.96.0.0/15", "118.96.0.0 - 118.97.255.255"),
        ("118.136.0.0/14", "118.136.0.0 - 118.139.255.255"),
        ("119.18.0.0/17", "119.18.0.0 - 119.18.127.255"),
        ("119.110.0.0/17", "119.110.0.0 - 119.110.127.255"),
        ("120.89.0.0/17", "120.89.0.0 - 120.89.127.255"),
        ("121.50.0.0/17", "121.50.0.0 - 121.50.127.255"),
        ("121.52.0.0/15", "121.52.0.0 - 121.53.255.255"),
        ("121.100.0.0/17", "121.100.0.0 - 121.100.127.255"),
        ("122.129.0.0/17", "122.129.0.0 - 122.129.127.255"),
        ("124.6.0.0/16", "124.6.0.0 - 124.6.255.255"),
        ("124.153.0.0/17", "124.153.0.0 - 124.153.127.255"),
        ("125.160.0.0/14", "125.160.0.0 - 125.163.255.255"),
        ("125.164.0.0/14", "125.164.0.0 - 125.167.255.255"),
        ("125.208.0.0/18", "125.208.0.0 - 125.208.63.255"),
        ("125.255.0.0/16", "125.255.0.0 - 125.255.255.255"),
        // Indosat
        ("114.8.0.0/15", "114.8.0.0 - 114.9.255.255"),
        ("139.0.0.0/16", "139.0.0.0 - 139.0.255.255"),
        ("139.192.0.0/12", "139.192.0.0 - 139.207.255.255"),
        ("139.228.0.0/16", "139.228.0.0 - 139.228.255.255"),
        ("140.0.0.0/16", "140.0.0.0 - 140.0.255.255"),
        ("175.136.0.0/14", "175.136.0.0 - 175.139.255.255"),
        ("175.140.0.0/18", "175.140.0.0 - 175.140.63.255"),
        ("180.214.0.0/17", "180.214.0.0 - 180.214.127.255"),
        ("180.240.0.0/12", "180.240.0.0 - 180.255.255.255"),
        ("182.0.0.0/12", "182.0.0.0 - 182.15.255.255"),
        ("182.16.0.0/16", "182.16.0.0 - 182.16.255.255"),
        ("182.23.0.0/17", "182.23.0.0 - 182.23.127.255"),
        ("182.29.0.0/17", "182.29.0.0 - 182.29.127.255"),
        ("182.253.0.0/17", "182.253.0.0 - 182.253.127.255"),
        ("183.91.0.0/16", "183.91.0.0 - 183.91.255.255"),
        ("202.0.0.0/10", "202.0.0.0 - 202.63.255.255"),
        ("202.73.0.0/18", "202.73.0.0 - 202.73.63.255"),
        ("202.80.0.0/18", "202.80.0.0 - 202.80.63.255"),
        ("202.93.0.0/18", "202.93.0.0 - 202.93.63.255"),
        ("202.138.0.0/18", "202.138.0.0 - 202.138.63.255"),
        ("202.146.0.0/18", "202.146.0.0 - 202.146.63.255"),
        ("202.152.0.0/17", "202.152.0.0 - 202.152.127.255"),
        ("202.162.0.0/18", "202.162.0.0 - 202.162.63.255"),
        ("202.173.0.0/18", "202.173.0.0 - 202.173.63.255"),
        ("202.180.0.0/18", "202.180.0.0 - 202.180.63.255"),
        ("202.191.0.0/18", "202.191.0.0 - 202.191.63.255"),
        ("203.0.0.0/10", "203.0.0.0 - 203.63.255.255"),
        ("203.77.0.0/18", "203.77.0.0 - 203.77.63.255"),
        ("203.123.0.0/18", "203.123.0.0 - 203.123.63.255"),
        ("203.142.0.0/18", "203.142.0.0 - 203.142.63.255"),
        ("203.161.0.0/18", "203.161.0.0 - 203.161.63.255"),
        ("203.174.0.0/18", "203.174.0.0 - 203.174.63.255"),
        ("203.189.0.0/18", "203.189.0.0 - 203.189.63.255"),
        ("203.209.0.0/18", "203.209.0.0 - 203.209.63.255"),
        ("203.222.0.0/18", "203.222.0.0 - 203.222.63.255"),
        ("203.223.0.0/18", "203.223.0.0 - 203.223.63.255"),
        ("210.0.0.0/10", "210.0.0.0 - 210.63.255.255"),
        ("222.0.0.0/12", "222.0.0.0 - 222.15.255.255"),
        ("222.124.0.0/17", "222.124.0.0 - 222.124.127.255"),
        ("222.165.0.0/18", "222.165.0.0 - 222.165.63.255"),
        ("223.255.0.0/17", "223.255.0.0 - 223.255.127.255"),
    ]);

    // Singapore - specific ranges (avoid overlapping with ID)
    ranges.insert("SG", vec![
        ("8.128.0.0/10", "8.128.0.0 - 8.191.255.255"),
        ("27.0.0.0/16", "27.0.0.0 - 27.0.255.255"),
        ("42.0.0.0/16", "42.0.0.0 - 42.0.255.255"),
        ("49.0.0.0/16", "49.0.0.0 - 49.0.255.255"),
        ("54.0.0.0/16", "54.0.0.0 - 54.0.255.255"),
        ("57.0.0.0/16", "57.0.0.0 - 57.0.255.255"),
        ("58.0.0.0/16", "58.0.0.0 - 58.0.255.255"),
        ("59.0.0.0/16", "59.0.0.0 - 59.0.255.255"),
        ("101.0.0.0/16", "101.0.0.0 - 101.0.255.255"),
        ("103.0.0.0/16", "103.0.0.0 - 103.0.255.255"),
        ("106.0.0.0/16", "106.0.0.0 - 106.0.255.255"),
        ("113.0.0.0/16", "113.0.0.0 - 113.0.255.255"),
        ("118.0.0.0/16", "118.0.0.0 - 118.0.255.255"),
        ("119.0.0.0/16", "119.0.0.0 - 119.0.255.255"),
        ("120.0.0.0/16", "120.0.0.0 - 120.0.255.255"),
        ("121.0.0.0/16", "121.0.0.0 - 121.0.255.255"),
        ("122.0.0.0/16", "122.0.0.0 - 122.0.255.255"),
        ("123.0.0.0/16", "123.0.0.0 - 123.0.255.255"),
        ("124.0.0.0/16", "124.0.0.0 - 124.0.255.255"),
        ("175.0.0.0/16", "175.0.0.0 - 175.0.255.255"),
        ("180.0.0.0/16", "180.0.0.0 - 180.0.255.255"),
        ("182.0.0.0/16", "182.0.0.0 - 182.0.255.255"),
        ("183.0.0.0/16", "183.0.0.0 - 183.0.255.255"),
        ("202.0.0.0/16", "202.0.0.0 - 202.0.255.255"),
        ("203.0.0.0/16", "203.0.0.0 - 203.0.255.255"),
        ("220.0.0.0/16", "220.0.0.0 - 220.0.255.255"),
        ("221.0.0.0/16", "221.0.0.0 - 221.0.255.255"),
        ("222.0.0.0/16", "222.0.0.0 - 222.0.255.255"),
    ]);

    // Malaysia - specific ranges
    ranges.insert("MY", vec![
        ("1.0.0.0/16", "1.0.0.0 - 1.0.255.255"),
        ("14.0.0.0/16", "14.0.0.0 - 14.0.255.255"),
        ("27.0.0.0/16", "27.0.0.0 - 27.0.255.255"),
        ("42.0.0.0/16", "42.0.0.0 - 42.0.255.255"),
        ("43.0.0.0/16", "43.0.0.0 - 43.0.255.255"),
        ("49.0.0.0/16", "49.0.0.0 - 49.0.255.255"),
        ("58.0.0.0/16", "58.0.0.0 - 58.0.255.255"),
        ("60.0.0.0/16", "60.0.0.0 - 60.0.255.255"),
        ("61.0.0.0/16", "61.0.0.0 - 61.0.255.255"),
        ("101.0.0.0/16", "101.0.0.0 - 101.0.255.255"),
        ("103.0.0.0/16", "103.0.0.0 - 103.0.255.255"),
        ("110.0.0.0/16", "110.0.0.0 - 110.0.255.255"),
        ("115.0.0.0/16", "115.0.0.0 - 115.0.255.255"),
        ("116.0.0.0/16", "116.0.0.0 - 116.0.255.255"),
        ("117.0.0.0/16", "117.0.0.0 - 117.0.255.255"),
        ("118.0.0.0/16", "118.0.0.0 - 118.0.255.255"),
        ("119.0.0.0/16", "119.0.0.0 - 119.0.255.255"),
        ("120.0.0.0/16", "120.0.0.0 - 120.0.255.255"),
        ("121.0.0.0/16", "121.0.0.0 - 121.0.255.255"),
        ("122.0.0.0/16", "122.0.0.0 - 122.0.255.255"),
        ("123.0.0.0/16", "123.0.0.0 - 123.0.255.255"),
        ("124.0.0.0/16", "124.0.0.0 - 124.0.255.255"),
        ("175.0.0.0/16", "175.0.0.0 - 175.0.255.255"),
        ("180.0.0.0/16", "180.0.0.0 - 180.0.255.255"),
        ("182.0.0.0/16", "182.0.0.0 - 182.0.255.255"),
        ("183.0.0.0/16", "183.0.0.0 - 183.0.255.255"),
        ("202.0.0.0/16", "202.0.0.0 - 202.0.255.255"),
        ("203.0.0.0/16", "203.0.0.0 - 203.0.255.255"),
    ]);

    // United States - specific ranges (avoid overlapping with others)
    ranges.insert("US", vec![
        ("3.0.0.0/8", "3.0.0.0 - 3.255.255.255"),
        ("4.0.0.0/8", "4.0.0.0 - 4.255.255.255"),
        ("6.0.0.0/8", "6.0.0.0 - 6.255.255.255"),
        ("7.0.0.0/8", "7.0.0.0 - 7.255.255.255"),
        ("8.0.0.0/8", "8.0.0.0 - 8.255.255.255"),
        ("9.0.0.0/8", "9.0.0.0 - 9.255.255.255"),
        ("11.0.0.0/8", "11.0.0.0 - 11.255.255.255"),
        ("12.0.0.0/8", "12.0.0.0 - 12.255.255.255"),
        ("13.0.0.0/8", "13.0.0.0 - 13.255.255.255"),
        ("15.0.0.0/8", "15.0.0.0 - 15.255.255.255"),
        ("16.0.0.0/8", "16.0.0.0 - 16.255.255.255"),
        ("17.0.0.0/8", "17.0.0.0 - 17.255.255.255"),
        ("18.0.0.0/8", "18.0.0.0 - 18.255.255.255"),
        ("20.0.0.0/8", "20.0.0.0 - 20.255.255.255"),
        ("23.0.0.0/8", "23.0.0.0 - 23.255.255.255"),
        ("24.0.0.0/8", "24.0.0.0 - 24.255.255.255"),
        ("32.0.0.0/8", "32.0.0.0 - 32.255.255.255"),
        ("34.0.0.0/8", "34.0.0.0 - 34.255.255.255"),
        ("35.0.0.0/8", "35.0.0.0 - 35.255.255.255"),
        ("40.0.0.0/8", "40.0.0.0 - 40.255.255.255"),
        ("44.0.0.0/8", "44.0.0.0 - 44.255.255.255"),
        ("45.0.0.0/8", "45.0.0.0 - 45.255.255.255"),
        ("47.0.0.0/8", "47.0.0.0 - 47.255.255.255"),
        ("48.0.0.0/8", "48.0.0.0 - 48.255.255.255"),
        ("50.0.0.0/8", "50.0.0.0 - 50.255.255.255"),
        ("52.0.0.0/8", "52.0.0.0 - 52.255.255.255"),
        ("54.0.0.0/8", "54.0.0.0 - 54.255.255.255"),
        ("63.0.0.0/8", "63.0.0.0 - 63.255.255.255"),
        ("64.0.0.0/8", "64.0.0.0 - 64.255.255.255"),
        ("65.0.0.0/8", "65.0.0.0 - 65.255.255.255"),
        ("66.0.0.0/8", "66.0.0.0 - 66.255.255.255"),
        ("67.0.0.0/8", "67.0.0.0 - 67.255.255.255"),
        ("68.0.0.0/8", "68.0.0.0 - 68.255.255.255"),
        ("69.0.0.0/8", "69.0.0.0 - 69.255.255.255"),
        ("70.0.0.0/8", "70.0.0.0 - 70.255.255.255"),
        ("71.0.0.0/8", "71.0.0.0 - 71.255.255.255"),
        ("72.0.0.0/8", "72.0.0.0 - 72.255.255.255"),
        ("73.0.0.0/8", "73.0.0.0 - 73.255.255.255"),
        ("74.0.0.0/8", "74.0.0.0 - 74.255.255.255"),
        ("75.0.0.0/8", "75.0.0.0 - 75.255.255.255"),
        ("76.0.0.0/8", "76.0.0.0 - 76.255.255.255"),
        ("96.0.0.0/8", "96.0.0.0 - 96.255.255.255"),
        ("97.0.0.0/8", "97.0.0.0 - 97.255.255.255"),
        ("98.0.0.0/8", "98.0.0.0 - 98.255.255.255"),
        ("99.0.0.0/8", "99.0.0.0 - 99.255.255.255"),
        ("104.0.0.0/8", "104.0.0.0 - 104.255.255.255"),
        ("107.0.0.0/8", "107.0.0.0 - 107.255.255.255"),
        ("108.0.0.0/8", "108.0.0.0 - 108.255.255.255"),
        ("142.0.0.0/8", "142.0.0.0 - 142.255.255.255"),
        ("143.0.0.0/8", "143.0.0.0 - 143.255.255.255"),
        ("144.0.0.0/8", "144.0.0.0 - 144.255.255.255"),
        ("157.0.0.0/8", "157.0.0.0 - 157.255.255.255"),
        ("158.0.0.0/8", "158.0.0.0 - 158.255.255.255"),
        ("160.0.0.0/8", "160.0.0.0 - 160.255.255.255"),
        ("161.0.0.0/8", "161.0.0.0 - 161.255.255.255"),
        ("162.0.0.0/8", "162.0.0.0 - 162.255.255.255"),
        ("163.0.0.0/8", "163.0.0.0 - 163.255.255.255"),
        ("164.0.0.0/8", "164.0.0.0 - 164.255.255.255"),
        ("165.0.0.0/8", "165.0.0.0 - 165.255.255.255"),
        ("166.0.0.0/8", "166.0.0.0 - 166.255.255.255"),
        ("167.0.0.0/8", "167.0.0.0 - 167.255.255.255"),
        ("168.0.0.0/8", "168.0.0.0 - 168.255.255.255"),
        ("169.0.0.0/8", "169.0.0.0 - 169.255.255.255"),
        ("170.0.0.0/8", "170.0.0.0 - 170.255.255.255"),
        ("172.0.0.0/8", "172.0.0.0 - 172.255.255.255"),
        ("173.0.0.0/8", "173.0.0.0 - 173.255.255.255"),
        ("174.0.0.0/8", "174.0.0.0 - 174.255.255.255"),
        ("184.0.0.0/8", "184.0.0.0 - 184.255.255.255"),
        ("198.0.0.0/8", "198.0.0.0 - 198.255.255.255"),
        ("199.0.0.0/8", "199.0.0.0 - 199.255.255.255"),
        ("204.0.0.0/8", "204.0.0.0 - 204.255.255.255"),
        ("205.0.0.0/8", "205.0.0.0 - 205.255.255.255"),
        ("206.0.0.0/8", "206.0.0.0 - 206.255.255.255"),
        ("207.0.0.0/8", "207.0.0.0 - 207.255.255.255"),
        ("208.0.0.0/8", "208.0.0.0 - 208.255.255.255"),
        ("209.0.0.0/8", "209.0.0.0 - 209.255.255.255"),
        ("216.0.0.0/8", "216.0.0.0 - 216.255.255.255"),
    ]);

    ranges
}

// TLD to country code mapping
fn get_tld_country() -> std::collections::HashMap<&'static str, &'static str> {
    let mut tld_map = std::collections::HashMap::new();

    // Indonesia
    tld_map.insert("id", "ID");
    tld_map.insert("co.id", "ID");
    tld_map.insert("or.id", "ID");
    tld_map.insert("go.id", "ID");
    tld_map.insert("sch.id", "ID");
    tld_map.insert("my.id", "ID");
    tld_map.insert("web.id", "ID");
    tld_map.insert("biz.id", "ID");
    tld_map.insert("net.id", "ID");
    tld_map.insert("mil.id", "ID");

    // Singapore
    tld_map.insert("sg", "SG");
    tld_map.insert("com.sg", "SG");
    tld_map.insert("org.sg", "SG");
    tld_map.insert("net.sg", "SG");
    tld_map.insert("edu.sg", "SG");
    tld_map.insert("gov.sg", "SG");

    // Malaysia
    tld_map.insert("my", "MY");
    tld_map.insert("com.my", "MY");
    tld_map.insert("net.my", "MY");
    tld_map.insert("org.my", "MY");
    tld_map.insert("edu.my", "MY");
    tld_map.insert("gov.my", "MY");

    // United States - we don't usually use .us for sites, but...
    tld_map.insert("us", "US");
    tld_map.insert("com.us", "US");
    tld_map.insert("net.us", "US");
    tld_map.insert("org.us", "US");

    // China
    tld_map.insert("cn", "CN");
    tld_map.insert("com.cn", "CN");
    tld_map.insert("net.cn", "CN");
    tld_map.insert("org.cn", "CN");
    tld_map.insert("gov.cn", "CN");

    // Japan
    tld_map.insert("jp", "JP");
    tld_map.insert("co.jp", "JP");
    tld_map.insert("ne.jp", "JP");
    tld_map.insert("or.jp", "JP");
    tld_map.insert("ac.jp", "JP");

    // UK
    tld_map.insert("uk", "GB");
    tld_map.insert("co.uk", "GB");
    tld_map.insert("org.uk", "GB");
    tld_map.insert("net.uk", "GB");
    tld_map.insert("ac.uk", "GB");
    tld_map.insert("gov.uk", "GB");

    // Germany
    tld_map.insert("de", "DE");

    // France
    tld_map.insert("fr", "FR");

    // Russia
    tld_map.insert("ru", "RU");
    tld_map.insert("com.ru", "RU");
    tld_map.insert("net.ru", "RU");
    tld_map.insert("org.ru", "RU");

    tld_map
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

fn check_country(input: &str, targets: &HashSet<String>) -> Result<Option<String>> {
    let input = input.trim();

    // Check if input is an IP address
    if input.parse::<IpAddr>().is_ok() {
        // For IP: Try IP range lookup first (fast)
        if let Ok(ip) = input.parse() {
            if let Some(country) = ip_to_country(ip) {
                return Ok(Some(country));
            }
        }
        // If not found in ranges, try WHOIS
        if let Ok(country) = get_whois_country_for_ip(input) {
            return Ok(Some(country));
        }
        return Ok(None);
    }

    // Otherwise treat as domain
    let domain = input.to_lowercase();

    // Quick check: TLD mapping (fastest)
    if let Some(&country) = get_tld_country().get(domain.split('.').last().unwrap_or("")) {
        return Ok(Some(country.to_string()));
    }

    // Do WHOIS lookup (most accurate)
    match get_whois_country(&domain) {
        Ok(country) => Ok(Some(country)),
        Err(_) => Ok(None),
    }
}

fn ip_to_country(ip: IpAddr) -> Option<String> {
    let ranges = get_country_ranges();

    for (country, cidr_list) in &ranges {
        for (cidr, _) in cidr_list.iter() {
            if let Ok((network, mask)) = parse_cidr(cidr) {
                if ip_in_network(ip, network, mask) {
                    return Some(country.to_string());
                }
            }
        }
    }
    None
}

fn ip_in_network(ip: IpAddr, network: IpAddr, mask: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip4), IpAddr::V4(net4)) => {
            let shift = 32 - mask as u32;
            (u32::from(ip4) >> shift) == (u32::from(net4) >> shift)
        }
        _ => false,
    }
}

fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid CIDR"));
    }
    let ip: IpAddr = parts[0].parse()?;
    let mask: u8 = parts[1].parse()?;
    Ok((ip, mask))
}

fn get_whois_country_for_ip(ip: &str) -> Result<String> {
    // For IP WHOIS, we need to query the appropriate RIR (Regional Internet Registry)
    // APNIC handles Asia-Pacific including Indonesia

    // Try APNIC first (most likely for Indonesia)
    if let Ok(country) = query_whois_server(ip, "whois.apnic.net") {
        return Ok(country);
    }

    // Fallback to RIPE
    if let Ok(country) = query_whois_server(ip, "whois.ripe.net") {
        return Ok(country);
    }

    // Fallback to ARIN
    if let Ok(country) = query_whois_server(ip, "whois.arin.net") {
        return Ok(country);
    }

    Err(anyhow!("Could not determine country for IP"))
}

fn query_whois_server(input: &str, server: &str) -> Result<String> {
    let ip = resolve_hostname(server)?;
    let addr = SocketAddr::new(ip, WHOIS_PORT);

    let mut stream = TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(10))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;

    // For IP queries, we usually need "n -" or just the IP
    let request = if server.contains("arin") {
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

fn get_whois_country(domain: &str) -> Result<String> {
    let ip = resolve_hostname("whois.iana.org")?;
    let addr = SocketAddr::new(ip, WHOIS_PORT);

    let mut stream = TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(10))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;

    let request = format!("{}\r\n", domain);
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
    let country_regex = Regex::new(r"(?i)country:\s*(\w{2})")?;

    if let Some(caps) = country_regex.captures(whois_data) {
        if let Some(country) = caps.get(1) {
            return Ok(country.as_str().to_uppercase());
        }
    }

    // Check for country name mentions
    let country_names: Vec<(&str, &str)> = vec![
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
        ("BRITAIN", "GB"),
        ("ENGLAND", "GB"),
    ];

    let lower = whois_data.to_lowercase();
    for (name, code) in country_names {
        if lower.contains(&name.to_lowercase()) {
            return Ok(code.to_string());
        }
    }

    Err(anyhow!("Could not determine country"))
}

fn resolve_hostname(hostname: &str) -> Result<IpAddr> {
    use dns_lookup::lookup_host;

    let ips = lookup_host(hostname)
        .map_err(|e| anyhow!("DNS lookup failed for {}: {}", hostname, e))?;

    ips.into_iter()
        .next()
        .ok_or_else(|| anyhow!("No IP address found for {}", hostname))
}
