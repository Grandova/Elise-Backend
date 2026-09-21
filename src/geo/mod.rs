pub mod dat;

pub use dat::{CountryIpList, GeoIpFile, GeoSiteFile, SiteGroupList};

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Clone)]
pub struct GeoEngine {
    geoip_file: Arc<RwLock<Option<GeoIpFile>>>,
    geosite_file: Arc<RwLock<Option<GeoSiteFile>>>,
    cached_countries: Arc<RwLock<HashMap<String, CountryIpList>>>,
    cached_sites: Arc<RwLock<HashMap<String, SiteGroupList>>>,
}

impl Default for GeoEngine {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl GeoEngine {
    pub fn new(geoip_path: Option<PathBuf>, geosite_path: Option<PathBuf>) -> Self {
        let mut engine = Self {
            geoip_file: Arc::new(RwLock::new(None)),
            geosite_file: Arc::new(RwLock::new(None)),
            cached_countries: Arc::new(RwLock::new(HashMap::new())),
            cached_sites: Arc::new(RwLock::new(HashMap::new())),
        };

        engine.init_files(geoip_path, geosite_path);
        engine
    }

    fn init_files(&mut self, custom_geoip: Option<PathBuf>, custom_geosite: Option<PathBuf>) {
        let geoip_candidates = vec![
            custom_geoip,
            Some(PathBuf::from("/etc/elise/geoip.dat")),
            Some(PathBuf::from("./geoip.dat")),
            Some(PathBuf::from("../geoip.dat")),
            Some(PathBuf::from("/usr/local/share/elise/geoip.dat")),
        ];

        for opt in geoip_candidates.into_iter().flatten() {
            if opt.exists() {
                match GeoIpFile::load_from_file(&opt) {
                    Ok(f) => {
                        info!(
                            "GeoEngine: Successfully loaded GeoIP database from {:?}",
                            opt
                        );
                        *self.geoip_file.write() = Some(f);
                        break;
                    }
                    Err(e) => {
                        warn!("GeoEngine: Failed to parse GeoIP at {:?}: {:?}", opt, e);
                    }
                }
            }
        }

        let geosite_candidates = vec![
            custom_geosite,
            Some(PathBuf::from("/etc/elise/geosite.dat")),
            Some(PathBuf::from("./geosite.dat")),
            Some(PathBuf::from("../geosite.dat")),
            Some(PathBuf::from("/usr/local/share/elise/geosite.dat")),
        ];

        for opt in geosite_candidates.into_iter().flatten() {
            if opt.exists() {
                match GeoSiteFile::load_from_file(&opt) {
                    Ok(f) => {
                        info!(
                            "GeoEngine: Successfully loaded GeoSite database from {:?}",
                            opt
                        );
                        *self.geosite_file.write() = Some(f);
                        break;
                    }
                    Err(e) => {
                        warn!("GeoEngine: Failed to parse GeoSite at {:?}: {:?}", opt, e);
                    }
                }
            }
        }
    }

    pub fn match_geoip(&self, country: &str, ip: IpAddr) -> bool {
        let code = country.trim().to_uppercase();

        {
            let cache = self.cached_countries.read();
            if let Some(list) = cache.get(&code) {
                return list.contains(ip);
            }
        }

        let file_guard = self.geoip_file.read();
        if let Some(geoip) = file_guard.as_ref() {
            if let Some(list) = geoip.load_country(&code) {
                let matched = list.contains(ip);
                drop(file_guard);
                self.cached_countries.write().insert(code, list);
                return matched;
            }
        }

        false
    }

    pub fn match_geosite(&self, tag: &str, domain: &str) -> bool {
        let group_tag = tag.trim().to_lowercase();

        {
            let cache = self.cached_sites.read();
            if let Some(group) = cache.get(&group_tag) {
                return group.matches(domain);
            }
        }

        let file_guard = self.geosite_file.read();
        if let Some(geosite) = file_guard.as_ref() {
            if let Some(group) = geosite.load_group(&group_tag) {
                let matched = group.matches(domain);
                drop(file_guard);
                self.cached_sites.write().insert(group_tag, group);
                return matched;
            }
        }

        false
    }

    pub fn preload_country(&self, country: &str) {
        let code = country.trim().to_uppercase();
        if self.cached_countries.read().contains_key(&code) {
            return;
        }
        if let Some(geoip) = self.geoip_file.read().as_ref() {
            if let Some(list) = geoip.load_country(&code) {
                self.cached_countries.write().insert(code, list);
            }
        }
    }

    pub fn preload_site_group(&self, tag: &str) {
        let group_tag = tag.trim().to_lowercase();
        if self.cached_sites.read().contains_key(&group_tag) {
            return;
        }
        if let Some(geosite) = self.geosite_file.read().as_ref() {
            if let Some(group) = geosite.load_group(&group_tag) {
                self.cached_sites.write().insert(group_tag, group);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_geo_engine_discovery_and_matching() {
        let engine = GeoEngine::new(None, None);
        if engine.geoip_file.read().is_none() || engine.geosite_file.read().is_none() {
            eprintln!("Skipping geo match test: geoip.dat or geosite.dat not present in current environment");
            return;
        }

        let alidns: IpAddr = IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5));
        let googledns: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        let cn_match = engine.match_geoip("CN", alidns);
        let google_match = engine.match_geoip("CN", googledns);

        println!(
            "223.5.5.5 in CN: {}, 8.8.8.8 in CN: {}",
            cn_match, google_match
        );
        assert!(cn_match);
        assert!(!google_match);

        let site_match = engine.match_geosite("cn", "baidu.com");
        println!("baidu.com in geosite:cn: {}", site_match);
        assert!(site_match);
    }
}
