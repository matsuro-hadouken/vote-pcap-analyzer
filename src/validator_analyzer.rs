// ============================================================================
// Validator Analyzer Module
// ============================================================================

use anyhow::Result;
use colored::*;
use std::collections::HashMap;
use std::path::Path;

use crate::pcap_processor::{PcapProcessor, RawPacket};
use crate::output_generator::{ValidatorResults, TimingRecord, PortStat};
use crate::solana_decoder;
use crate::{ValidatorConfig};
use crate::validator_resolver::ValidatorResolver;

#[derive(Debug, Default)]
pub struct ValidatorInfo {
    pub ip: String,
    pub name: Option<String>,
    pub identity_address: Option<String>,
    pub version: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub asn: Option<String>,
    pub asn_organization: Option<String>,
}

impl ValidatorInfo {
    pub fn new(ip: String) -> Self {
        Self {
            ip,
            ..Default::default()
        }
    }

    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    pub fn with_identity(mut self, identity: String) -> Self {
        self.identity_address = Some(identity);
        self
    }

    pub fn with_version(mut self, version: String) -> Self {
        self.version = Some(version);
        self
    }

    pub fn with_location(mut self, country: String, city: String) -> Self {
        self.country = Some(country);
        self.city = Some(city);
        self
    }

    pub fn with_asn(mut self, asn: String, asn_org: String) -> Self {
        self.asn = Some(asn);
        self.asn_organization = Some(asn_org);
        self
    }
}

pub struct ValidatorAnalyzer {
    validators: HashMap<String, ValidatorConfig>,
    target_ips: Vec<String>,
    custom_port_mappings: HashMap<u16, String>,
}

impl Default for ValidatorAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidatorAnalyzer {
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
            target_ips: Vec::new(),
            custom_port_mappings: HashMap::new(),
        }
    }

    pub fn set_custom_port_mappings(&mut self, mappings: HashMap<u16, String>) {
        self.custom_port_mappings = mappings;
    }

    // Create mapping from all possible IPs (current + historical) to validator identity
    pub fn create_ip_to_identity_mapping(&self, historical_mappings: Option<&HashMap<String, String>>) -> HashMap<String, String> {
        let mut ip_mapping = HashMap::new();
        
        for (current_ip, config) in &self.validators {
            // Map current IP to identity
            ip_mapping.insert(current_ip.clone(), config.identity_address.clone());
        }
        
        // Add historical IP mappings if provided
        if let Some(historical) = historical_mappings {
            for (historical_ip, identity) in historical {
                ip_mapping.insert(historical_ip.clone(), identity.clone());
            }
        }
        
        ip_mapping
    }

    pub fn add_validator(&mut self, validator_info: ValidatorInfo) {
        let config = ValidatorConfig {
            name: validator_info.name.unwrap_or_else(|| format!("Validator_{}", validator_info.ip.replace('.', "_"))),
            identity_address: validator_info.identity_address.unwrap_or_else(|| format!("Unknown_Identity_{}", validator_info.ip)),
            version: validator_info.version.unwrap_or_else(|| "unknown".to_string()),
            country: validator_info.country.unwrap_or_else(|| "unknown".to_string()),
            city: validator_info.city.unwrap_or_else(|| "unknown".to_string()),
            asn: validator_info.asn.unwrap_or_else(|| "unknown".to_string()),
            asn_organization: validator_info.asn_organization.unwrap_or_else(|| "unknown".to_string()),
        };
        self.validators.insert(validator_info.ip.clone(), config);
        self.target_ips.push(validator_info.ip);
    }

    pub fn add_validator_simple(&mut self, ip: String, name: Option<String>, identity_address: Option<String>) {
        // Simple validator addition method
        let default_name = format!("Validator_{}", ip.replace('.', "_"));
        let default_identity = format!("Unknown_Identity_{}", ip);
        
        let validator_info = ValidatorInfo::new(ip)
            .with_name(name.unwrap_or(default_name))
            .with_identity(identity_address.unwrap_or(default_identity));
        self.add_validator(validator_info);
    }

    pub async fn load_validators_from_identity_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let content = std::fs::read_to_string(path)?;
        let resolver = ValidatorResolver::new();
        
        println!("Loading validators from identity-only file...");
        
        for line in content.lines() {
            let identity = line.trim();
            if identity.starts_with('#') || identity.is_empty() {
                continue;
            }
            
            println!("Resolving validator: {}", identity);
            
            match resolver.get_validator_info(identity).await {
                Ok(info) => {
                    println!("{} Resolved: {} -> {} ({})", 
                             "[✓]".green().bold(), identity, info.name.cyan(), info.current_ip.yellow());
                    
                    let validator_info = ValidatorInfo::new(info.current_ip.clone())
                        .with_name(info.name.clone())
                        .with_identity(identity.to_string())
                        .with_version(info.version.clone())
                        .with_location(info.country.clone(), info.city.clone())
                        .with_asn(info.asn.clone(), info.asn_organization.clone());
                    
                    self.add_validator(validator_info);
                }
                Err(e) => {
                    eprintln!("{} Failed to resolve validator {}: {}", 
                             "[✗]".red().bold(), identity.yellow(), e.to_string().red());
                    eprintln!("   Skipping this validator...");
                }
            }
        }
        
        Ok(())
    }

    /// Validate identity format (exactly 44 characters)
    fn validate_identity(identity: &str) -> Result<()> {
        if identity.len() != 44 {
            return Err(anyhow::anyhow!(
                "Invalid identity length: '{}' (length: {})\n\
                Identity must be exactly 44 characters.\n\
                Example: 'GwHH8ciFhR8vejWCqmg8FWZUCNtubPY2esALvy5tBvji'", 
                identity, identity.len()
            ));
        }
        Ok(())
    }

    pub async fn load_validator_from_identity_string(&mut self, identity: &str) -> Result<()> {
        Self::validate_identity(identity)?;

        let resolver = ValidatorResolver::new();
        
        match resolver.get_validator_info(identity).await {
            Ok(info) => {
                println!("{} Resolved: {} -> {} ({})", 
                         "[✓]".green().bold(), identity, info.name.cyan(), info.current_ip.yellow());
                
                let validator_info = ValidatorInfo::new(info.current_ip.clone())
                    .with_name(info.name.clone())
                    .with_identity(identity.to_string())
                    .with_version(info.version.clone())
                    .with_location(info.country.clone(), info.city.clone())
                    .with_asn(info.asn.clone(), info.asn_organization.clone());
                
                self.add_validator(validator_info);
                Ok(())
            }
            Err(e) => {
                eprintln!("{} Failed to resolve validator {}: {}", 
                         "[✗]".red().bold(), identity.yellow(), e.to_string().red());
                Err(e)
            }
        }
    }

    pub async fn load_validator_from_identity_with_pcap(&mut self, identity: &str, pcap_path: &str) -> Result<()> {
        Self::validate_identity(identity)?;

        let resolver = ValidatorResolver::new();
        
        match resolver.resolve_validator(identity, pcap_path).await {
            Ok(resolved) => {
                println!("{} Resolved with historical lookup: {} -> {} ({})", 
                         "[✓]".green().bold(), identity, resolved.info.name.cyan(), resolved.info.current_ip.yellow());
                
                if resolved.active_ips.len() > 1 {
                    println!("   {} Active IPs in PCAP: {}", 
                             "[INFO]".blue().bold(), 
                             resolved.active_ips.join(", ").yellow());
                } else if resolved.active_ips.is_empty() {
                    println!("   {} No matching IPs found in PCAP (checked {} historical IPs)", 
                             "[WARN]".yellow().bold(), 
                             resolved.all_possible_ips.len());
                }
                
                // Use primary active IP or fallback to current IP
                let primary_ip = resolved.active_ips.first()
                    .unwrap_or(&resolved.info.current_ip);
                
                let validator_info = ValidatorInfo::new(primary_ip.clone())
                    .with_name(resolved.info.name.clone())
                    .with_identity(identity.to_string())
                    .with_version(resolved.info.version.clone())
                    .with_location(resolved.info.country.clone(), resolved.info.city.clone())
                    .with_asn(resolved.info.asn.clone(), resolved.info.asn_organization.clone());
                
                self.add_validator(validator_info);
                Ok(())
            }
            Err(e) => {
                eprintln!("{} Failed to resolve validator with PCAP check {}: {}", 
                         "[✗]".red().bold(), identity.yellow(), e.to_string().red());
                Err(e)
            }
        }
    }

    // Helper methods for testing
    pub fn get_validator_count(&self) -> usize {
        self.validators.len()
    }
    
    pub fn get_target_ips(&self) -> &[String] {
        &self.target_ips
    }

    pub fn get_validator_name(&self, ip: &str) -> Option<&String> {
        self.validators.get(ip).map(|config| &config.name)
    }

    pub fn get_validators(&self) -> &HashMap<String, ValidatorConfig> {
        &self.validators
    }

    pub fn get_custom_port_mappings(&self) -> &HashMap<u16, String> {
        &self.custom_port_mappings
    }

    pub fn process_pcap(&self, pcap_file: &str) -> Result<(HashMap<String, ValidatorResults>, usize)> {
        let mut processor = PcapProcessor::new(self.target_ips.clone());
        processor.set_custom_port_mappings(self.custom_port_mappings.clone());
        
        println!("Processing pcap file...");
        println!("Looking for {} validators", self.target_ips.len());
        let (packets, total_processed) = processor.process_pcap(pcap_file)?;
        
        let mut results: HashMap<String, ValidatorResults> = HashMap::new();
        
        for (ip, packets) in packets {
            if !packets.is_empty() {
                let validator_result = self.analyze_validator(&ip, packets)?;
                results.insert(ip, validator_result);
            }
        }
        
        Ok((results, total_processed as usize))
    }

    fn analyze_validator(&self, ip: &str, mut packets: Vec<RawPacket>) -> Result<ValidatorResults> {
        packets.sort_by(|a, b| a.timestamp.partial_cmp(&b.timestamp).unwrap());
        
        let first_timestamp = packets[0].timestamp;
        let validator_config = self.validators.get(ip);
        let validator_name = validator_config
            .map(|v| v.name.clone())
            .unwrap_or_else(|| format!("Unknown_{}", ip));

        let mut timing_records = Vec::new();
        let mut port_stats: HashMap<u16, PortStat> = HashMap::new();
        let mut prev_timestamp = first_timestamp;
        
        // Caching mechanism: cache decoded transactions to avoid repeated work
        let mut decoded_cache: HashMap<String, Option<solana_decoder::SolanaTransaction>> = HashMap::new();
        let mut unique_patterns = std::collections::HashSet::new();
        let mut duplicate_count = 0;

        for packet in &packets {
            let since_first = packet.timestamp - first_timestamp;
            let since_prev = packet.timestamp - prev_timestamp;
            prev_timestamp = packet.timestamp;

            // Track unique vs duplicate patterns
            if unique_patterns.contains(&packet.data_suffix) {
                duplicate_count += 1;
            } else {
                unique_patterns.insert(packet.data_suffix.clone());
            }

            // Cached decoding: decode each pattern once
            let is_transaction;
            let mut signature_count = None;
            let mut signatures = Vec::new();
            let mut recent_blockhash = None;
            let mut instruction_count = None;
            let mut vote_account = None;
            let mut validator_identity = None;

            if !decoded_cache.contains_key(&packet.data_suffix) {
                // First time seeing this pattern - try to decode
                if solana_decoder::is_potential_transaction(&packet.data_hex) {
                    match solana_decoder::decode_solana_transaction(&packet.data_hex) {
                        Ok(tx) => {
                            decoded_cache.insert(packet.data_suffix.clone(), Some(tx));
                        }
                        Err(_) => {
                            decoded_cache.insert(packet.data_suffix.clone(), None);
                        }
                    }
                } else {
                    decoded_cache.insert(packet.data_suffix.clone(), None);
                }
            }

            // Use cached result
            if let Some(Some(tx)) = decoded_cache.get(&packet.data_suffix) {
                is_transaction = true;
                signature_count = Some(tx.signatures.len() as u8);
                signatures = tx.signatures.clone();
                recent_blockhash = Some(tx.recent_blockhash.clone());
                instruction_count = Some(tx.instruction_count);
                
                // Extract vote account and validator identity if available
                vote_account = tx.vote_account.clone();
                validator_identity = tx.validator_identity.clone();
            } else {
                is_transaction = false;
            }

            // Update port statistics
            let port_stat = port_stats.entry(packet.dest_port).or_insert(PortStat {
                port: packet.dest_port,
                service_name: packet.solana_service.clone(),
                packet_count: 0,
                total_bytes: 0,
                avg_packet_size: 0.0,
            });
            port_stat.packet_count += 1;
            port_stat.total_bytes += packet.payload_size as u64;
            port_stat.avg_packet_size = port_stat.total_bytes as f64 / port_stat.packet_count as f64;

            timing_records.push(TimingRecord {
                packet_number: packet.packet_number,
                timestamp: packet.timestamp,
                since_first,
                since_prev,
                dest_port: packet.dest_port,
                solana_service: packet.solana_service.clone(),
                protocol: packet.protocol.clone(),
                payload_size: packet.payload_size,
                data_suffix: packet.data_suffix.clone(),
                is_transaction,
                signature_count,
                signatures: signatures.clone(),
                recent_blockhash: recent_blockhash.clone(),
                instruction_count,
                vote_account: vote_account.clone(),
                validator_identity: validator_identity.clone(),
            });
        }

        let avg_interval = if let (Some(first), Some(last)) =
            (packets.first(), packets.last())
        {
            let count = packets.len();
            if count > 1 {
                let total_time = last.timestamp - first.timestamp;
                total_time / (count as f64 - 1.0)
            } else {
                0.0
            }
        } else {
            0.0
        };

        Ok(ValidatorResults {
            ip_address: ip.to_string(),
            validator_name,
            first_timestamp,
            total_packets: packets.len(),
            unique_transactions: unique_patterns.len(),
            total_duplicates: duplicate_count,
            avg_interval,
            timing_records,
            port_stats,
            // Use ValidatorConfig fields or defaults
            version: validator_config.map(|v| v.version.clone()).unwrap_or_else(|| "unknown".to_string()),
            country: validator_config.map(|v| v.country.clone()).unwrap_or_else(|| "unknown".to_string()),
            city: validator_config.map(|v| v.city.clone()).unwrap_or_else(|| "unknown".to_string()),
            asn: validator_config.map(|v| v.asn.clone()).unwrap_or_else(|| "unknown".to_string()),
            asn_organization: validator_config.map(|v| v.asn_organization.clone()).unwrap_or_else(|| "unknown".to_string()),
        })
    }
}