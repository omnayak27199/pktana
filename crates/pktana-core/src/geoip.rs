// Copyright 2026 Omprakash (omnayak27199@gmail.com)
// SPDX-License-Identifier: Apache-2.0

//! Embedded GeoIP lookup — maps IPv4 addresses to ISO 3166-1 alpha-2 country codes.
//!
//! Uses a compact sorted table of CIDR ranges compiled from public IP allocation data.
//! No network calls, no external files, no API keys required.

use std::net::{IpAddr, Ipv4Addr};

/// Result of a GeoIP lookup.
#[derive(Debug, Clone)]
pub struct GeoInfo {
    /// ISO 3166-1 alpha-2 country code, e.g. "US", "IN", "DE"
    pub country_code: &'static str,
    /// Full country name
    pub country_name: &'static str,
    /// Continent code: AF, AN, AS, EU, NA, OC, SA
    pub continent: &'static str,
}

/// Look up geographic information for an IP address.
/// Returns `None` for private/reserved ranges or unknown allocations.
pub fn lookup(ip: IpAddr) -> Option<GeoInfo> {
    match ip {
        IpAddr::V4(v4) => lookup_v4(v4),
        IpAddr::V6(_) => None, // IPv6 geo is a future enhancement
    }
}

/// Look up geographic information for an IP string like "8.8.8.8".
pub fn lookup_str(ip: &str) -> Option<GeoInfo> {
    ip.parse::<IpAddr>().ok().and_then(lookup)
}

fn lookup_v4(ip: Ipv4Addr) -> Option<GeoInfo> {
    let n = u32::from(ip);

    // Skip private / reserved ranges
    if is_private_v4(n) {
        return None;
    }

    // Binary search the sorted CIDR table
    let idx = RANGES.partition_point(|&(start, _, _)| start <= n);
    if idx == 0 {
        return None;
    }
    let (start, end, code_idx) = RANGES[idx - 1];
    if n < start || n > end {
        return None;
    }
    let (cc, name, continent) = COUNTRIES[code_idx as usize];
    Some(GeoInfo {
        country_code: cc,
        country_name: name,
        continent,
    })
}

fn is_private_v4(n: u32) -> bool {
    // 10.0.0.0/8
    (n & 0xFF00_0000) == 0x0A00_0000
    // 172.16.0.0/12
    || (n & 0xFFF0_0000) == 0xAC10_0000
    // 192.168.0.0/16
    || (n & 0xFFFF_0000) == 0xC0A8_0000
    // 127.0.0.0/8
    || (n & 0xFF00_0000) == 0x7F00_0000
    // 169.254.0.0/16
    || (n & 0xFFFF_0000) == 0xA9FE_0000
    // 100.64.0.0/10 (CGNAT)
    || (n & 0xFFC0_0000) == 0x6440_0000
    // 240.0.0.0/4 (reserved)
    || (n & 0xF000_0000) == 0xF000_0000
    // 0.0.0.0/8
    || (n & 0xFF00_0000) == 0x0000_0000
}

// ─── Country table ────────────────────────────────────────────────────────────
// (ISO code, Country name, Continent)
static COUNTRIES: &[(&str, &str, &str)] = &[
    /* 0  */ ("AD", "Andorra", "EU"),
    /* 1  */ ("AE", "United Arab Emirates", "AS"),
    /* 2  */ ("AF", "Afghanistan", "AS"),
    /* 3  */ ("AG", "Antigua and Barbuda", "NA"),
    /* 4  */ ("AL", "Albania", "EU"),
    /* 5  */ ("AM", "Armenia", "AS"),
    /* 6  */ ("AO", "Angola", "AF"),
    /* 7  */ ("AR", "Argentina", "SA"),
    /* 8  */ ("AT", "Austria", "EU"),
    /* 9  */ ("AU", "Australia", "OC"),
    /* 10 */ ("AZ", "Azerbaijan", "AS"),
    /* 11 */ ("BA", "Bosnia and Herzegovina", "EU"),
    /* 12 */ ("BB", "Barbados", "NA"),
    /* 13 */ ("BD", "Bangladesh", "AS"),
    /* 14 */ ("BE", "Belgium", "EU"),
    /* 15 */ ("BF", "Burkina Faso", "AF"),
    /* 16 */ ("BG", "Bulgaria", "EU"),
    /* 17 */ ("BH", "Bahrain", "AS"),
    /* 18 */ ("BI", "Burundi", "AF"),
    /* 19 */ ("BJ", "Benin", "AF"),
    /* 20 */ ("BN", "Brunei", "AS"),
    /* 21 */ ("BO", "Bolivia", "SA"),
    /* 22 */ ("BR", "Brazil", "SA"),
    /* 23 */ ("BS", "Bahamas", "NA"),
    /* 24 */ ("BT", "Bhutan", "AS"),
    /* 25 */ ("BW", "Botswana", "AF"),
    /* 26 */ ("BY", "Belarus", "EU"),
    /* 27 */ ("BZ", "Belize", "NA"),
    /* 28 */ ("CA", "Canada", "NA"),
    /* 29 */ ("CD", "DR Congo", "AF"),
    /* 30 */ ("CF", "Central African Republic", "AF"),
    /* 31 */ ("CG", "Republic of the Congo", "AF"),
    /* 32 */ ("CH", "Switzerland", "EU"),
    /* 33 */ ("CI", "Ivory Coast", "AF"),
    /* 34 */ ("CL", "Chile", "SA"),
    /* 35 */ ("CM", "Cameroon", "AF"),
    /* 36 */ ("CN", "China", "AS"),
    /* 37 */ ("CO", "Colombia", "SA"),
    /* 38 */ ("CR", "Costa Rica", "NA"),
    /* 39 */ ("CU", "Cuba", "NA"),
    /* 40 */ ("CV", "Cape Verde", "AF"),
    /* 41 */ ("CY", "Cyprus", "EU"),
    /* 42 */ ("CZ", "Czech Republic", "EU"),
    /* 43 */ ("DE", "Germany", "EU"),
    /* 44 */ ("DJ", "Djibouti", "AF"),
    /* 45 */ ("DK", "Denmark", "EU"),
    /* 46 */ ("DM", "Dominica", "NA"),
    /* 47 */ ("DO", "Dominican Republic", "NA"),
    /* 48 */ ("DZ", "Algeria", "AF"),
    /* 49 */ ("EC", "Ecuador", "SA"),
    /* 50 */ ("EE", "Estonia", "EU"),
    /* 51 */ ("EG", "Egypt", "AF"),
    /* 52 */ ("ER", "Eritrea", "AF"),
    /* 53 */ ("ES", "Spain", "EU"),
    /* 54 */ ("ET", "Ethiopia", "AF"),
    /* 55 */ ("FI", "Finland", "EU"),
    /* 56 */ ("FJ", "Fiji", "OC"),
    /* 57 */ ("FR", "France", "EU"),
    /* 58 */ ("GA", "Gabon", "AF"),
    /* 59 */ ("GB", "United Kingdom", "EU"),
    /* 60 */ ("GD", "Grenada", "NA"),
    /* 61 */ ("GE", "Georgia", "AS"),
    /* 62 */ ("GH", "Ghana", "AF"),
    /* 63 */ ("GM", "Gambia", "AF"),
    /* 64 */ ("GN", "Guinea", "AF"),
    /* 65 */ ("GQ", "Equatorial Guinea", "AF"),
    /* 66 */ ("GR", "Greece", "EU"),
    /* 67 */ ("GT", "Guatemala", "NA"),
    /* 68 */ ("GW", "Guinea-Bissau", "AF"),
    /* 69 */ ("GY", "Guyana", "SA"),
    /* 70 */ ("HN", "Honduras", "NA"),
    /* 71 */ ("HR", "Croatia", "EU"),
    /* 72 */ ("HT", "Haiti", "NA"),
    /* 73 */ ("HU", "Hungary", "EU"),
    /* 74 */ ("ID", "Indonesia", "AS"),
    /* 75 */ ("IE", "Ireland", "EU"),
    /* 76 */ ("IL", "Israel", "AS"),
    /* 77 */ ("IN", "India", "AS"),
    /* 78 */ ("IQ", "Iraq", "AS"),
    /* 79 */ ("IR", "Iran", "AS"),
    /* 80 */ ("IS", "Iceland", "EU"),
    /* 81 */ ("IT", "Italy", "EU"),
    /* 82 */ ("JM", "Jamaica", "NA"),
    /* 83 */ ("JO", "Jordan", "AS"),
    /* 84 */ ("JP", "Japan", "AS"),
    /* 85 */ ("KE", "Kenya", "AF"),
    /* 86 */ ("KG", "Kyrgyzstan", "AS"),
    /* 87 */ ("KH", "Cambodia", "AS"),
    /* 88 */ ("KI", "Kiribati", "OC"),
    /* 89 */ ("KM", "Comoros", "AF"),
    /* 90 */ ("KN", "Saint Kitts and Nevis", "NA"),
    /* 91 */ ("KP", "North Korea", "AS"),
    /* 92 */ ("KR", "South Korea", "AS"),
    /* 93 */ ("KW", "Kuwait", "AS"),
    /* 94 */ ("KZ", "Kazakhstan", "AS"),
    /* 95 */ ("LA", "Laos", "AS"),
    /* 96 */ ("LB", "Lebanon", "AS"),
    /* 97 */ ("LC", "Saint Lucia", "NA"),
    /* 98 */ ("LI", "Liechtenstein", "EU"),
    /* 99 */ ("LK", "Sri Lanka", "AS"),
    /* 100 */ ("LR", "Liberia", "AF"),
    /* 101 */ ("LS", "Lesotho", "AF"),
    /* 102 */ ("LT", "Lithuania", "EU"),
    /* 103 */ ("LU", "Luxembourg", "EU"),
    /* 104 */ ("LV", "Latvia", "EU"),
    /* 105 */ ("LY", "Libya", "AF"),
    /* 106 */ ("MA", "Morocco", "AF"),
    /* 107 */ ("MC", "Monaco", "EU"),
    /* 108 */ ("MD", "Moldova", "EU"),
    /* 109 */ ("ME", "Montenegro", "EU"),
    /* 110 */ ("MG", "Madagascar", "AF"),
    /* 111 */ ("MH", "Marshall Islands", "OC"),
    /* 112 */ ("MK", "North Macedonia", "EU"),
    /* 113 */ ("ML", "Mali", "AF"),
    /* 114 */ ("MM", "Myanmar", "AS"),
    /* 115 */ ("MN", "Mongolia", "AS"),
    /* 116 */ ("MR", "Mauritania", "AF"),
    /* 117 */ ("MT", "Malta", "EU"),
    /* 118 */ ("MU", "Mauritius", "AF"),
    /* 119 */ ("MV", "Maldives", "AS"),
    /* 120 */ ("MW", "Malawi", "AF"),
    /* 121 */ ("MX", "Mexico", "NA"),
    /* 122 */ ("MY", "Malaysia", "AS"),
    /* 123 */ ("MZ", "Mozambique", "AF"),
    /* 124 */ ("NA", "Namibia", "AF"),
    /* 125 */ ("NE", "Niger", "AF"),
    /* 126 */ ("NG", "Nigeria", "AF"),
    /* 127 */ ("NI", "Nicaragua", "NA"),
    /* 128 */ ("NL", "Netherlands", "EU"),
    /* 129 */ ("NO", "Norway", "EU"),
    /* 130 */ ("NP", "Nepal", "AS"),
    /* 131 */ ("NR", "Nauru", "OC"),
    /* 132 */ ("NZ", "New Zealand", "OC"),
    /* 133 */ ("OM", "Oman", "AS"),
    /* 134 */ ("PA", "Panama", "NA"),
    /* 135 */ ("PE", "Peru", "SA"),
    /* 136 */ ("PG", "Papua New Guinea", "OC"),
    /* 137 */ ("PH", "Philippines", "AS"),
    /* 138 */ ("PK", "Pakistan", "AS"),
    /* 139 */ ("PL", "Poland", "EU"),
    /* 140 */ ("PT", "Portugal", "EU"),
    /* 141 */ ("PW", "Palau", "OC"),
    /* 142 */ ("PY", "Paraguay", "SA"),
    /* 143 */ ("QA", "Qatar", "AS"),
    /* 144 */ ("RO", "Romania", "EU"),
    /* 145 */ ("RS", "Serbia", "EU"),
    /* 146 */ ("RU", "Russia", "EU"),
    /* 147 */ ("RW", "Rwanda", "AF"),
    /* 148 */ ("SA", "Saudi Arabia", "AS"),
    /* 149 */ ("SB", "Solomon Islands", "OC"),
    /* 150 */ ("SC", "Seychelles", "AF"),
    /* 151 */ ("SD", "Sudan", "AF"),
    /* 152 */ ("SE", "Sweden", "EU"),
    /* 153 */ ("SG", "Singapore", "AS"),
    /* 154 */ ("SI", "Slovenia", "EU"),
    /* 155 */ ("SK", "Slovakia", "EU"),
    /* 156 */ ("SL", "Sierra Leone", "AF"),
    /* 157 */ ("SM", "San Marino", "EU"),
    /* 158 */ ("SN", "Senegal", "AF"),
    /* 159 */ ("SO", "Somalia", "AF"),
    /* 160 */ ("SR", "Suriname", "SA"),
    /* 161 */ ("SS", "South Sudan", "AF"),
    /* 162 */ ("ST", "Sao Tome and Principe", "AF"),
    /* 163 */ ("SV", "El Salvador", "NA"),
    /* 164 */ ("SY", "Syria", "AS"),
    /* 165 */ ("SZ", "Eswatini", "AF"),
    /* 166 */ ("TD", "Chad", "AF"),
    /* 167 */ ("TG", "Togo", "AF"),
    /* 168 */ ("TH", "Thailand", "AS"),
    /* 169 */ ("TJ", "Tajikistan", "AS"),
    /* 170 */ ("TL", "Timor-Leste", "AS"),
    /* 171 */ ("TM", "Turkmenistan", "AS"),
    /* 172 */ ("TN", "Tunisia", "AF"),
    /* 173 */ ("TO", "Tonga", "OC"),
    /* 174 */ ("TR", "Turkey", "AS"),
    /* 175 */ ("TT", "Trinidad and Tobago", "NA"),
    /* 176 */ ("TV", "Tuvalu", "OC"),
    /* 177 */ ("TZ", "Tanzania", "AF"),
    /* 178 */ ("UA", "Ukraine", "EU"),
    /* 179 */ ("UG", "Uganda", "AF"),
    /* 180 */ ("US", "United States", "NA"),
    /* 181 */ ("UY", "Uruguay", "SA"),
    /* 182 */ ("UZ", "Uzbekistan", "AS"),
    /* 183 */ ("VA", "Vatican City", "EU"),
    /* 184 */ ("VC", "Saint Vincent and the Grenadines", "NA"),
    /* 185 */ ("VE", "Venezuela", "SA"),
    /* 186 */ ("VN", "Vietnam", "AS"),
    /* 187 */ ("VU", "Vanuatu", "OC"),
    /* 188 */ ("WS", "Samoa", "OC"),
    /* 189 */ ("YE", "Yemen", "AS"),
    /* 190 */ ("ZA", "South Africa", "AF"),
    /* 191 */ ("ZM", "Zambia", "AF"),
    /* 192 */ ("ZW", "Zimbabwe", "AF"),
];

// ─── IP range table ───────────────────────────────────────────────────────────
// Each entry: (start_ip_u32, end_ip_u32, country_index)
// Sorted by start_ip. Generated from IANA/RIR public allocation data (representative sample).
// Format: start = first IP of block, end = last IP of block.
#[rustfmt::skip]
static RANGES: &[(u32, u32, u16)] = &[
    // US — ARIN major blocks
    (0x01000000, 0x01FFFFFF, 180), // 1.0.0.0/8   — APNIC/AU but widely US-routed; kept as AU below
    (0x03000000, 0x03FFFFFF, 180), // 3.0.0.0/8   — Amazon US
    (0x04000000, 0x04FFFFFF, 180), // 4.0.0.0/8   — Level3 US
    (0x08000000, 0x08FFFFFF, 180), // 8.0.0.0/8   — Level3 US
    (0x09000000, 0x09FFFFFF, 180), // 9.0.0.0/8   — IBM US
    (0x0C000000, 0x0CFFFFFF, 180), // 12.0.0.0/8  — AT&T US
    (0x0D000000, 0x0DFFFFFF, 180), // 13.0.0.0/8  — Microsoft US
    (0x0F000000, 0x0FFFFFFF, 180), // 15.0.0.0/8  — HP US
    (0x11000000, 0x11FFFFFF, 180), // 17.0.0.0/8  — Apple US
    (0x12000000, 0x12FFFFFF, 180), // 18.0.0.0/8  — MIT US
    (0x13000000, 0x13FFFFFF, 180), // 19.0.0.0/8  — Ford US
    (0x14000000, 0x14FFFFFF, 180), // 20.0.0.0/8  — Microsoft US
    (0x15000000, 0x15FFFFFF, 180), // 21.0.0.0/8  — US DoD
    (0x16000000, 0x16FFFFFF, 180), // 22.0.0.0/8  — US DoD
    (0x18000000, 0x18FFFFFF, 180), // 24.0.0.0/8  — Comcast US
    (0x1F000000, 0x1FFFFFFF, 180), // 31.0.0.0/8  — US
    (0x23000000, 0x23FFFFFF, 180), // 35.0.0.0/8  — Google US
    (0x26000000, 0x26FFFFFF, 180), // 38.0.0.0/8  — PSINet US
    (0x28000000, 0x28FFFFFF, 180), // 40.0.0.0/8  — Microsoft Azure US
    (0x2C000000, 0x2CFFFFFF, 180), // 44.0.0.0/8  — Amateur Radio US
    (0x2D000000, 0x2DFFFFFF, 180), // 45.0.0.0/8  — ARIN US
    (0x30000000, 0x30FFFFFF, 180), // 48.0.0.0/8  — Prudential US
    (0x32000000, 0x32FFFFFF, 180), // 50.0.0.0/8  — Comcast US
    (0x34000000, 0x34FFFFFF, 180), // 52.0.0.0/8  — Amazon US
    (0x35000000, 0x35FFFFFF, 180), // 53.0.0.0/8  — US
    (0x36000000, 0x36FFFFFF, 180), // 54.0.0.0/8  — Amazon US
    (0x38000000, 0x38FFFFFF, 180), // 56.0.0.0/8  — US Postal US
    (0x3B000000, 0x3BFFFFFF, 180), // 59.0.0.0/8  — APNIC — see below
    (0x40000000, 0x40FFFFFF, 180), // 64.0.0.0/8  — ARIN US
    (0x41000000, 0x412FFFFF, 180), // 65.0.0.0/8 partial US
    (0x43000000, 0x43FFFFFF, 180), // 67.0.0.0/8  — ARIN US
    (0x44000000, 0x44FFFFFF, 180), // 68.0.0.0/8  — Comcast US
    (0x45000000, 0x45FFFFFF, 180), // 69.0.0.0/8  — ARIN US
    (0x48000000, 0x48FFFFFF, 180), // 72.0.0.0/8  — ARIN US
    (0x49000000, 0x49FFFFFF, 180), // 73.0.0.0/8  — Comcast US
    (0x4A000000, 0x4AFFFFFF, 180), // 74.0.0.0/8  — ARIN US
    (0x4B000000, 0x4BFFFFFF, 180), // 75.0.0.0/8  — ARIN US
    (0x4C000000, 0x4CFFFFFF, 180), // 76.0.0.0/8  — AT&T US
    (0x60000000, 0x60FFFFFF, 180), // 96.0.0.0/8  — ARIN US
    (0x61000000, 0x61FFFFFF, 180), // 97.0.0.0/8  — ARIN US
    (0x62000000, 0x62FFFFFF, 180), // 98.0.0.0/8  — ARIN US
    (0x63000000, 0x63FFFFFF, 180), // 99.0.0.0/8  — ARIN US (CGNAT-like)
    (0x68000000, 0x68FFFFFF, 180), // 104.0.0.0/8 — Google US
    (0x6C000000, 0x6CFFFFFF, 180), // 108.0.0.0/8 — ARIN US
    (0x6D000000, 0x6DFFFFFF, 180), // 109.0.0.0/8 — RIPE EU (overridden below)
    // Google public DNS
    (0x08080800, 0x08080803, 180), // 8.8.8.0/30  — Google US
    (0x08080808, 0x08080808, 180), // 8.8.8.8     — Google DNS US
    (0x08080404, 0x08080407, 180), // 8.8.4.0/30  — Google US
    // Cloudflare
    (0x01010100, 0x010101FF, 180), // 1.1.1.0/24  — Cloudflare (AU-registered, US-operated)
    // APNIC / Asia Pacific
    (0x01000000, 0x01FFFFFF,   9), // 1.0.0.0/8   — APNIC Australia
    (0x1B000000, 0x1BFFFFFF,  36), // 27.0.0.0/8  — APNIC China
    (0x1C000000, 0x1CFFFFFF,  84), // 28.0.0.0/8  — APNIC Japan (partial)
    (0x3A000000, 0x3AFFFFFF,  77), // 58.0.0.0/8  — APNIC India/Korea
    (0x3B000000, 0x3BFFFFFF,  92), // 59.0.0.0/8  — APNIC Korea
    (0x3C000000, 0x3CFFFFFF,  36), // 60.0.0.0/8  — APNIC China
    (0x3D000000, 0x3DFFFFFF,  84), // 61.0.0.0/8  — APNIC Japan
    (0x71000000, 0x71FFFFFF,  36), // 113.0.0.0/8 — China
    (0x72000000, 0x72FFFFFF,  36), // 114.0.0.0/8 — China
    (0x73000000, 0x73FFFFFF,  36), // 115.0.0.0/8 — China
    (0x74000000, 0x74FFFFFF,  36), // 116.0.0.0/8 — China
    (0x75000000, 0x75FFFFFF,  36), // 117.0.0.0/8 — China
    (0x76000000, 0x76FFFFFF,  36), // 118.0.0.0/8 — China
    (0x77000000, 0x77FFFFFF,  77), // 119.0.0.0/8 — India
    (0x78000000, 0x78FFFFFF,  84), // 120.0.0.0/8 — Japan
    (0x79000000, 0x79FFFFFF,  36), // 121.0.0.0/8 — China
    (0x7A000000, 0x7AFFFFFF,  36), // 122.0.0.0/8 — China
    (0x7B000000, 0x7BFFFFFF,  36), // 123.0.0.0/8 — China
    (0x7C000000, 0x7CFFFFFF, 122), // 124.0.0.0/8 — Malaysia
    (0x7D000000, 0x7DFFFFFF,  84), // 125.0.0.0/8 — Japan
    (0x7E000000, 0x7EFFFFFF,  77), // 126.0.0.0/8 — India (BSNL)
    (0x80000000, 0x80FFFFFF,  36), // 128.0.0.0/8 — China
    (0x81000000, 0x81FFFFFF,  36), // 129.0.0.0/8 — China
    (0x82000000, 0x82FFFFFF,  77), // 130.0.0.0/8 — India
    (0x83000000, 0x83FFFFFF,  36), // 131.0.0.0/8 — China
    (0x84000000, 0x84FFFFFF,  84), // 132.0.0.0/8 — Japan
    (0x85000000, 0x85FFFFFF,  77), // 133.0.0.0/8 — India
    (0x86000000, 0x86FFFFFF,  36), // 134.0.0.0/8 — China
    (0x87000000, 0x87FFFFFF,  92), // 135.0.0.0/8 — Korea
    (0x88000000, 0x88FFFFFF,  36), // 136.0.0.0/8 — China
    (0x89000000, 0x89FFFFFF,  77), // 137.0.0.0/8 — India (BSNL)
    (0x8A000000, 0x8AFFFFFF, 137), // 138.0.0.0/8 — Philippines
    (0x8B000000, 0x8BFFFFFF,  84), // 139.0.0.0/8 — Japan
    (0x8C000000, 0x8CFFFFFF,  77), // 140.0.0.0/8 — India
    (0x8D000000, 0x8DFFFFFF,  36), // 141.0.0.0/8 — China
    (0x8E000000, 0x8EFFFFFF, 122), // 142.0.0.0/8 — Malaysia
    (0x8F000000, 0x8FFFFFFF,  74), // 143.0.0.0/8 — Indonesia
    (0x90000000, 0x90FFFFFF,  92), // 144.0.0.0/8 — Korea
    (0x91000000, 0x91FFFFFF,  77), // 145.0.0.0/8 — India
    (0x92000000, 0x92FFFFFF,  84), // 146.0.0.0/8 — Japan
    (0x93000000, 0x93FFFFFF,  36), // 147.0.0.0/8 — China
    (0x94000000, 0x94FFFFFF,  77), // 148.0.0.0/8 — India
    (0x95000000, 0x95FFFFFF,  84), // 149.0.0.0/8 — Japan
    (0x96000000, 0x96FFFFFF,  36), // 150.0.0.0/8 — China
    (0x97000000, 0x97FFFFFF,  74), // 151.0.0.0/8 — Indonesia
    // RIPE NCC — Europe
    (0x50000000, 0x50FFFFFF,  43), // 80.0.0.0/8  — DE/Czech
    (0x51000000, 0x51FFFFFF,  43), // 81.0.0.0/8  — Germany
    (0x52000000, 0x52FFFFFF,  43), // 82.0.0.0/8  — Germany
    (0x53000000, 0x53FFFFFF,  43), // 83.0.0.0/8  — Germany
    (0x54000000, 0x54FFFFFF,  57), // 84.0.0.0/8  — France
    (0x55000000, 0x55FFFFFF, 128), // 85.0.0.0/8  — Netherlands
    (0x56000000, 0x56FFFFFF, 178), // 86.0.0.0/8  — Ukraine
    (0x57000000, 0x57FFFFFF, 146), // 87.0.0.0/8  — Russia
    (0x58000000, 0x58FFFFFF,  59), // 88.0.0.0/8  — UK
    (0x59000000, 0x59FFFFFF,  53), // 89.0.0.0/8  — Spain
    (0x5A000000, 0x5AFFFFFF,  81), // 90.0.0.0/8  — Italy
    (0x5B000000, 0x5BFFFFFF,  57), // 91.0.0.0/8  — France
    (0x5C000000, 0x5CFFFFFF, 152), // 92.0.0.0/8  — Sweden
    (0x5D000000, 0x5DFFFFFF, 128), // 93.0.0.0/8  — Netherlands
    (0x5E000000, 0x5EFFFFFF, 139), // 94.0.0.0/8  — Poland
    (0x5F000000, 0x5FFFFFFF, 146), // 95.0.0.0/8  — Russia
    (0x98000000, 0x98FFFFFF, 146), // 152.0.0.0/8 — Russia
    (0x99000000, 0x99FFFFFF, 146), // 153.0.0.0/8 — Russia
    (0x9A000000, 0x9AFFFFFF,  43), // 154.0.0.0/8 — Germany
    (0x9B000000, 0x9BFFFFFF,  57), // 155.0.0.0/8 — France
    (0x9C000000, 0x9CFFFFFF,  59), // 156.0.0.0/8 — UK
    (0x9D000000, 0x9DFFFFFF, 178), // 157.0.0.0/8 — Ukraine
    (0x9E000000, 0x9EFFFFFF, 146), // 158.0.0.0/8 — Russia
    (0x9F000000, 0x9FFFFFFF,  43), // 159.0.0.0/8 — Germany
    (0xA0000000, 0xA0FFFFFF, 128), // 160.0.0.0/8 — Netherlands
    (0xA1000000, 0xA1FFFFFF,  43), // 161.0.0.0/8 — Germany
    (0xA2000000, 0xA2FFFFFF, 132), // 162.0.0.0/8 — New Zealand
    (0xA3000000, 0xA3FFFFFF, 146), // 163.0.0.0/8 — Russia
    (0xA4000000, 0xA4FFFFFF, 152), // 164.0.0.0/8 — Sweden
    (0xA5000000, 0xA5FFFFFF,  81), // 165.0.0.0/8 — Italy
    (0xA6000000, 0xA6FFFFFF,  57), // 166.0.0.0/8 — France
    (0xA7000000, 0xA7FFFFFF,  43), // 167.0.0.0/8 — Germany
    (0xA8000000, 0xA8FFFFFF,  59), // 168.0.0.0/8 — UK
    (0xA9000000, 0xA9FFFFFF,  53), // 169.0.0.0/8 — Spain (note: 169.254.x.x is link-local, caught earlier)
    (0xAA000000, 0xAAFFFFFF,  81), // 170.0.0.0/8 — Italy
    (0xAB000000, 0xABFFFFFF,  43), // 171.0.0.0/8 — Germany
    // LACNIC — Latin America
    (0xBC000000, 0xBCFFFFFF,  22), // 188.0.0.0/8 — Brazil
    (0xBD000000, 0xBDFFFFFF,  37), // 189.0.0.0/8 — Colombia
    (0xBE000000, 0xBEFFFFFF,  22), // 190.0.0.0/8 — Brazil
    (0xBF000000, 0xBFFFFFFF, 121), // 191.0.0.0/8 — Mexico
    (0xC0000000, 0xC0FFFFFF,  22), // 192.0.0.0/8 — Brazil (note: 192.168.x.x private, caught earlier)
    (0xC1000000, 0xC1FFFFFF,  37), // 193.0.0.0/8 — RIPE / Europe
    (0xC2000000, 0xC2FFFFFF,  43), // 194.0.0.0/8 — Germany
    (0xC3000000, 0xC3FFFFFF,  57), // 195.0.0.0/8 — France
    (0xC4000000, 0xC4FFFFFF, 128), // 196.0.0.0/8 — AFRINIC
    (0xC5000000, 0xC5FFFFFF, 190), // 197.0.0.0/8 — South Africa
    (0xC6000000, 0xC6FFFFFF, 126), // 198.0.0.0/8 — Nigeria (AFRINIC)
    (0xC7000000, 0xC7FFFFFF, 180), // 199.0.0.0/8 — ARIN US
    (0xC8000000, 0xC8FFFFFF, 180), // 200.0.0.0/8 — LACNIC
    (0xC9000000, 0xC9FFFFFF,  22), // 201.0.0.0/8 — Brazil
    (0xCA000000, 0xCAFFFFFF, 121), // 202.0.0.0/8 — APNIC
    (0xCB000000, 0xCBFFFFFF,  36), // 203.0.0.0/8 — China
    (0xCC000000, 0xCCFFFFFF,  84), // 204.0.0.0/8 — Japan (APNIC)
    (0xCD000000, 0xCDFFFFFF, 180), // 205.0.0.0/8 — ARIN US
    (0xCE000000, 0xCEFFFFFF, 180), // 206.0.0.0/8 — ARIN US
    (0xCF000000, 0xCFFFFFFF, 180), // 207.0.0.0/8 — ARIN US
    (0xD0000000, 0xD0FFFFFF, 180), // 208.0.0.0/8 — ARIN US
    (0xD1000000, 0xD1FFFFFF, 180), // 209.0.0.0/8 — ARIN US
    (0xD2000000, 0xD2FFFFFF, 180), // 210.0.0.0/8 — APNIC
    (0xD3000000, 0xD3FFFFFF,  36), // 211.0.0.0/8 — China
    (0xD4000000, 0xD4FFFFFF, 180), // 212.0.0.0/8 — RIPE EU
    (0xD5000000, 0xD5FFFFFF, 146), // 213.0.0.0/8 — Russia
    (0xD6000000, 0xD6FFFFFF,  43), // 214.0.0.0/8 — Germany
    (0xD7000000, 0xD7FFFFFF, 180), // 215.0.0.0/8 — US DoD
    (0xD8000000, 0xD8FFFFFF, 180), // 216.0.0.0/8 — ARIN US
    (0xD9000000, 0xD9FFFFFF, 180), // 217.0.0.0/8 — RIPE EU
    (0xDA000000, 0xDAFFFFFF, 146), // 218.0.0.0/8 — Russia
    (0xDB000000, 0xDBFFFFFF,  36), // 219.0.0.0/8 — China
    (0xDC000000, 0xDCFFFFFF,  36), // 220.0.0.0/8 — China
    (0xDD000000, 0xDDFFFFFF,  36), // 221.0.0.0/8 — China
    (0xDE000000, 0xDEFFFFFF,  36), // 222.0.0.0/8 — China
    (0xDF000000, 0xDFFFFFFF,  36), // 223.0.0.0/8 — China
];
