// src/sources/stubs.rs
// Este arquivo contém stubs vazios para sources que ainda não foram implementados

use crate::sources::Source;
use crate::types::{RustFinderError, SourceInfo, SubdomainResult};
use crate::session::Session;
use async_trait::async_trait;

// Macro para criar stubs rapidamente
macro_rules! create_stub_source {
    ($name:ident, $source_name:expr) => {
        #[derive(Debug, Clone)]
        pub struct $name {
            name: String,
        }

        impl $name {
            pub fn new() -> Self {
                Self {
                    name: $source_name.to_string(),
                }
            }
        }

        #[async_trait]
        impl Source for $name {
            fn name(&self) -> &str {
                &self.name
            }

            fn info(&self) -> SourceInfo {
                SourceInfo {
                    name: self.name().to_string(),
                    needs_key: false,
                    is_default: false,
                }
            }

            fn clone_source(&self) -> Box<dyn Source> {
                Box::new(self.clone())
            }

            async fn enumerate(&self, _domain: &str, _session: &Session) -> Result<Vec<SubdomainResult>, RustFinderError> {
                // Stub - not implemented yet
                Ok(vec![])
            }
        }
    };
}

// Create stub sources
// create_stub_source!(AlienvaultSource, "alienvault");
// create_stub_source!(AnubisSource, "anubis");
// create_stub_source!(BevigilSource, "bevigil");
// create_stub_source!(BufferoverSource, "bufferover");
// create_stub_source!(BuiltwithSource, "builtwith");
// create_stub_source!(C99Source, "c99");
// create_stub_source!(CensysSource, "censys");
// create_stub_source!(CertspotterSource, "certspotter");
// create_stub_source!(ChinazSource, "chinaz");
// create_stub_source!(CommoncrawlSource, "commoncrawl");
// create_stub_source!(DigitalyamaSource, "digitalyama");
// create_stub_source!(DigitorusSource, "digitorus");
// create_stub_source!(DnsdbSource, "dnsdb");
// create_stub_source!(DnsdumpsterSource, "dnsdumpster");
// create_stub_source!(DnsrepoSource, "dnsrepo");
// create_stub_source!(FacebookSource, "facebook");
// create_stub_source!(FofaSource, "fofa");
// create_stub_source!(FullhuntSource, "fullhunt");
// create_stub_source!(HudsonrockSource, "hudsonrock");
// create_stub_source!(HunterSource, "hunter");
// create_stub_source!(IntelxSource, "intelx");
// create_stub_source!(LeakixSource, "leakix");
// create_stub_source!(PugreconSource, "pugrecon");
// create_stub_source!(QuakeSource, "quake");
// create_stub_source!(RapiddnsSource, "rapiddns");
// create_stub_source!(RedhuntlabsSource, "redhuntlabs");
// create_stub_source!(RobtexSource, "robtex");
// create_stub_source!(RsecloudSource, "rsecloud");
// create_stub_source!(SitedossierSource, "sitedossier");
// create_stub_source!(ThreatbookSource, "threatbook");
// create_stub_source!(ThreatcrowdSource, "threatcrowd");
// create_stub_source!(WaybackarchiveSource, "waybackarchive");
// create_stub_source!(WhoisxmlapiSource, "whoisxmlapi");
// create_stub_source!(ZoomeyeapiSource, "zoomeyeapi");