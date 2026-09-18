pub mod client;
pub mod resolver;
pub mod router;
pub mod rules;
pub mod wire;

pub use client::{parse_dns_endpoint, DnsClient, DnsEndpoint};
pub use resolver::DNSResolver;
pub use router::RuleBasedDNSManager;
pub use rules::{CompiledDnsRule, DnsRulesTable, DomainMatcher};
