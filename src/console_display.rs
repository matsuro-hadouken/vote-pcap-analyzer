use colored::*;
use crate::output_generator::{ValidatorResults, TimingRecord};
use std::collections::HashMap;

pub struct ConsoleDisplay;

impl ConsoleDisplay {
    pub fn print_detailed_analysis(results: &HashMap<String, ValidatorResults>) {
        Self::print_detailed_analysis_with_processed_count(results, 0);
    }

    pub fn print_detailed_analysis_with_processed_count(results: &HashMap<String, ValidatorResults>, total_processed: u64) {
        for (ip, analysis) in results {
            Self::print_validator_analysis_with_processed_count(ip, analysis, total_processed);
            println!(); // Blank line between validators
        }
    }

    fn print_validator_analysis_with_processed_count(ip: &str, analysis: &ValidatorResults, total_processed: u64) {
        // Header
        println!("{}: {} ({})", "VALIDATOR ANALYSIS".cyan().bold(), analysis.validator_name.white(), ip.dimmed());
        println!("{}", "═".repeat(80).cyan());
        println!();

        // Packet Analysis Table - SHOW ALL PACKETS
        Self::print_packet_table_with_limit(&analysis.timing_records, 0);
        
        // Network Statistics
        Self::print_network_stats_with_processed_count(analysis, total_processed);
    }

    fn print_packet_table_with_limit(records: &[TimingRecord], max_display_packets: usize) {
        const TABLE_WIDTH: usize = 140;
        
        println!("{}", format!("{:<8} {:<33} {:<12} {:<12} {:<8} {:<15} {:<8} {:<6} {:<10} {:<2}", 
            "#PKT", "TIMESTAMP", "SINCE_FIRST", "SINCE_PREV", "DSTPORT", "PORT_DESC", "PROTOCOL", "SIZE", "DATA_SUFFIX", "TX").white().bold());
        println!("{}", "─".repeat(TABLE_WIDTH).white());

        // Track suffix colors for duplicates
        let mut suffix_colors: HashMap<String, bool> = HashMap::new();
        let mut color_toggle = false;

        let display_count = if max_display_packets == 0 {
            records.len() // No limit if 0
        } else {
            std::cmp::min(records.len(), max_display_packets)
        };
        let records_to_show = &records[..display_count];

        for record in records_to_show {
            // Suffix duplicate detection using color alternation
            if !suffix_colors.contains_key(&record.data_suffix) {
                suffix_colors.insert(record.data_suffix.clone(), color_toggle);
                color_toggle = !color_toggle;
            }
            
            let is_first_color = suffix_colors[&record.data_suffix];
            let colored_suffix = if is_first_color {
                record.data_suffix.green()
            } else {
                record.data_suffix.yellow()
            };

            // Port identification with distinct colors
            let colored_port = match record.dest_port {
                8003 => format!("{:<8}", record.dest_port).red(),
                8004 => format!("{:<8}", record.dest_port).yellow(),
                8005 => format!("{:<8}", record.dest_port).green(),
                8008 => format!("{:<8}", record.dest_port).dimmed(),
                8009 => format!("{:<8}", record.dest_port).magenta(),
                30004 => format!("{:<8}", record.dest_port).yellow(),
                30005 => format!("{:<8}", record.dest_port).green(),
                _ => {
                    // Port colors using modulo indexing
                    let colors = [
                        |s: String| s.red(), |s: String| s.yellow(), |s: String| s.green(), |s: String| s.magenta(),
                        |s: String| s.cyan(), |s: String| s.white(), |s: String| s.bright_red(), |s: String| s.bright_yellow(),
                    ];
                    let color_index = (record.dest_port as usize) % colors.len();
                    colors[color_index](format!("{:<8}", record.dest_port))
                }
            };

            // Service name formatting
            let clean_port_desc = if record.solana_service.starts_with("unknown_") {
                "unknown".to_string()
            } else {
                record.solana_service.clone()
            };

            // Port description coloring scheme
            let port_desc = match record.dest_port {
                8003 => format!("{:<15}", clean_port_desc).red(),
                8004 => format!("{:<15}", clean_port_desc).yellow(),
                8005 => format!("{:<15}", clean_port_desc).green(),
                8008 => format!("{:<15}", clean_port_desc).dimmed(),
                8009 => format!("{:<15}", clean_port_desc).magenta(),
                30004 => format!("{:<15}", clean_port_desc).yellow(),
                30005 => format!("{:<15}", clean_port_desc).green(),
                _ => {
                    // Colors for unmapped ports
                    let colors = [
                        |s: String| s.red(),           // Red
                        |s: String| s.yellow(),        // Yellow  
                        |s: String| s.green(),         // Green
                        |s: String| s.magenta(),       // Magenta
                        |s: String| s.cyan(),          // Cyan
                        |s: String| s.white(),         // White
                        |s: String| s.bright_red(),    // Bright Red
                        |s: String| s.bright_yellow(), // Bright Yellow
                    ];
                    let color_index = (record.dest_port as usize) % colors.len();
                    colors[color_index](format!("{:<15}", clean_port_desc))
                }
            };

            // Color-code protocol types with consistent formatting
            let colored_protocol = match record.protocol.as_str() {
                "UDP" => format!("{:<8}", record.protocol).bright_blue(),
                "QUIC" => format!("{:<8}", record.protocol).bright_magenta(),
                _ => format!("{:<8}", record.protocol).white(),
            };

            // Format timestamp with Solana log precision (nanoseconds)
            let timestamp_str = {
                use std::time::UNIX_EPOCH;
                let duration = std::time::Duration::from_secs_f64(record.timestamp);
                let datetime = UNIX_EPOCH + duration;
                let datetime: chrono::DateTime<chrono::Utc> = datetime.into();
                datetime.format("%Y-%m-%dT%H:%M:%S%.9fZ").to_string()
            };

            // Timing analysis: gap detection using 0.1s threshold
            let since_first_colored = {
                let value = record.since_first;
                if value == 0.0 { 
                    format!("{:.6}", value).bright_cyan()  // Session start
                } else {
                    let prev_interval = record.since_prev;
                    if prev_interval >= 0.1 {
                        format!("{:.6}", value).cyan()      // After gap
                    } else {
                        format!("{:.6}", value).dimmed()    // In burst
                    }
                }
            };

            let since_prev_colored = {
                let value = record.since_prev;
                if value >= 0.1 { 
                    format!("{:.6}", value).cyan()         // Gap boundary
                } else { 
                    format!("{:.6}", value).dimmed()       // Burst interval
                }
            };

            // Payload size classification
            let size_colored = match record.payload_size {
                0..=100 => format!("{:<6}", record.payload_size).dimmed(),
                101..=500 => format!("{:<6}", record.payload_size).white(),
                501..=1000 => format!("{:<6}", record.payload_size).yellow(),
                1001.. => format!("{:<6}", record.payload_size).red(),
            };

            // Transaction indicator
            let tx_indicator = if record.is_transaction {
                "✓".green()
            } else {
                "✗".red()
            };

            println!("{:<8} {:<33} {:<12} {:<12} {:<8} {:<15} {:<8} {} {} {}", 
                record.packet_number,
                timestamp_str.dimmed(),                    // Subdued timestamp
                since_first_colored,                       // Pattern-aware timing
                since_prev_colored,                        // Pattern-aware timing
                colored_port,
                port_desc,
                colored_protocol,
                size_colored.dimmed(),                     // Subdued size (same as timestamp)
                colored_suffix,
                tx_indicator
            );
        }

        // Show summary if there are more packets
        if max_display_packets > 0 && records.len() > max_display_packets {
            println!("{}", "─".repeat(140).dimmed());
            println!("{}", format!("... showing first {} of {} total packets", 
                max_display_packets, records.len()).dimmed().italic());
        }
    }

    fn print_network_stats_with_processed_count(analysis: &ValidatorResults, total_processed: u64) {
        println!();
        let header = if total_processed > 0 {
            format!("NETWORK BEHAVIOR STATISTICS - Processed: {} | Validator: {}", 
                total_processed.to_string().yellow(), 
                analysis.total_packets.to_string().green())
        } else {
            "NETWORK BEHAVIOR STATISTICS".to_string()
        };
        println!("{}", header.white().bold());
        println!("{}", "═".repeat(80).cyan());
        
        // Port Distribution:
        println!("{}", "Port Distribution:".white().bold());
        let mut ports: Vec<_> = analysis.port_stats.values().collect();
        ports.sort_by_key(|p| p.port);
        
        for port_stat in ports {
            let percentage = (port_stat.packet_count as f64 / analysis.total_packets as f64) * 100.0;
            
            // Remove "unknown_" prefix from service names
            let clean_service_name = if port_stat.service_name.starts_with("unknown_") {
                "unknown".to_string()
            } else {
                port_stat.service_name.clone()
            };
            
            let colored_port = match port_stat.port {
                8003 => format!("{:<6}", port_stat.port).red(),
                8004 => format!("{:<6}", port_stat.port).bright_yellow(),
                8005 => format!("{:<6}", port_stat.port).green(),
                8008 => format!("{:<6}", port_stat.port).dimmed(),
                8009 => format!("{:<6}", port_stat.port).magenta(),
                30004 => format!("{:<6}", port_stat.port).bright_blue(),
                30005 => format!("{:<6}", port_stat.port).bright_cyan(),
                _ => {
                    // Colors for unmapped ports
                    let colors = [
                        |s: String| s.red(),           // Red
                        |s: String| s.green(),         // Green  
                        |s: String| s.yellow(),        // Yellow
                        |s: String| s.blue(),          // Blue
                        |s: String| s.magenta(),       // Magenta
                        |s: String| s.cyan(),          // Cyan
                        |s: String| s.bright_red(),    // Bright Red
                        |s: String| s.bright_green(),  // Bright Green
                    ];
                    let color_index = (port_stat.port as usize) % colors.len();
                    colors[color_index](format!("{:<6}", port_stat.port))
                }
            };
            
            println!("  {} {:<12} {:<15} - {} avg bytes", 
                colored_port,
                clean_service_name.cyan(),
                format!("{} packets ({:.1}%)", port_stat.packet_count, percentage).bright_yellow(),
                port_stat.avg_packet_size as u64
            );
        }

        println!();
        println!("{}", "Timing Analysis:".white().bold());
        
        // Calculate timing metrics (exclude repair packets from calculations)
        let transactions: Vec<_> = analysis.timing_records.iter()
            .filter(|r| r.is_transaction && r.dest_port != 8008)
            .collect();
        
        let (avg_duplicate_interval, avg_block_interval, total_transaction_duration) = 
            Self::calculate_timing_metrics(&transactions);

        // Calculate non-repair records timing for duration calculations
        let mut non_repair_records_timing: Vec<_> = analysis.timing_records.iter().filter(|r| r.dest_port != 8008).collect();
        non_repair_records_timing.sort_by(|a, b| a.timestamp.partial_cmp(&b.timestamp).unwrap());

        // Calculate total duration excluding repair packets - from first to last non-repair packet
        let transaction_total_duration = if let (Some(first), Some(last)) =
            (non_repair_records_timing.first(), non_repair_records_timing.last())
        {
            last.timestamp - first.timestamp
        } else {
            0.0
        };

        // Calculate overall duration including all packets
        let overall_duration = if let (Some(first), Some(last)) = (analysis.timing_records.first(), analysis.timing_records.last()) {
            last.timestamp - first.timestamp
        } else { 0.0 };

        // Calculate non-repair average interval
        let non_repair_avg_interval = if let (Some(first), Some(last)) =
            (non_repair_records_timing.first(), non_repair_records_timing.last())
        {
            if non_repair_records_timing.len() > 1 {
                (last.timestamp - first.timestamp) / (non_repair_records_timing.len() as f64 - 1.0)
            } else {
                0.0
            }
        } else {
            0.0
        };

        println!("  Avg Interval (excl repair): {} seconds", format!("{:.6}", non_repair_avg_interval).green());
        println!("  Avg Duplicate Interval: {} seconds", format!("{:.6}", avg_duplicate_interval).cyan());
        println!("  Avg Block Interval: {} seconds", format!("{:.6}", avg_block_interval).blue());
        println!("  Transaction Duration: {} seconds", format!("{:.6}", total_transaction_duration).yellow());
        println!("  Voting Duration: {} seconds", format!("{:.6}", transaction_total_duration).bright_yellow());
        
        // Display overall duration when repair packets extend timeline >0.1s
        if (overall_duration - transaction_total_duration).abs() > 0.1 {
            println!("  Total Duration (incl repair): {} seconds", format!("{:.6}", overall_duration).dimmed());
        }
        
        println!("  Total Packets: {}", analysis.total_packets.to_string().bright_green());
        println!("  Unique Patterns: {}", analysis.unique_transactions.to_string().bright_yellow());
        println!("  Duplicates: {}", analysis.total_duplicates.to_string().red());
    }

    fn calculate_timing_metrics(transactions: &[&TimingRecord]) -> (f64, f64, f64) {
        if transactions.len() < 2 {
            return (0.0, 0.0, 0.0);
        }

        // Group transactions by suffix to find duplicates and blocks
        let mut suffix_groups: HashMap<String, Vec<&TimingRecord>> = HashMap::new();
        for transaction in transactions {
            suffix_groups.entry(transaction.data_suffix.clone())
                .or_default()
                .push(transaction);
        }

        // Calculate average interval within duplicate groups
        let mut duplicate_intervals = Vec::new();
        for group in suffix_groups.values() {
            if group.len() > 1 {
                for i in 1..group.len() {
                    let interval = group[i].timestamp - group[i-1].timestamp;
                    duplicate_intervals.push(interval);
                }
            }
        }

        // Calculate average interval between different transaction blocks
        let mut block_intervals = Vec::new();
        let mut sorted_suffixes: Vec<_> = suffix_groups.keys().collect();
        sorted_suffixes.sort();
        
        for i in 1..sorted_suffixes.len() {
            let prev_suffix = sorted_suffixes[i-1];
            let curr_suffix = sorted_suffixes[i];
            
            if let (Some(prev_group), Some(curr_group)) = (suffix_groups.get(prev_suffix), suffix_groups.get(curr_suffix)) {
                if let (Some(prev_last), Some(curr_first)) = (prev_group.last(), curr_group.first()) {
                    let interval = curr_first.timestamp - prev_last.timestamp;
                    block_intervals.push(interval);
                }
            }
        }

        // Calculate transaction duration (first to last transaction, excluding repair)
        let transaction_duration = if let (Some(first), Some(last)) = (transactions.first(), transactions.last()) {
            last.timestamp - first.timestamp
        } else { 0.0 };

        let avg_duplicate_interval = if !duplicate_intervals.is_empty() {
            duplicate_intervals.iter().sum::<f64>() / duplicate_intervals.len() as f64
        } else { 0.0 };

        let avg_block_interval = if !block_intervals.is_empty() {
            block_intervals.iter().sum::<f64>() / block_intervals.len() as f64
        } else { 0.0 };

        (avg_duplicate_interval, avg_block_interval, transaction_duration)
    }
}