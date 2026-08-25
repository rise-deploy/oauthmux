//! Embeddable OAuth/OIDC multiplexing engine.
//!
//! A host can provide instances from any dynamic store and mount two-segment
//! routes without depending on a standalone config provider:
//!
//! ```no_run
//! use oauthmux_core::{router, InstanceMap, KeyStrategy, MuxConfig, XChaChaSealer};
//! use std::sync::Arc;
//! let instances = InstanceMap::new(); // Populate from the host database.
//! let config = MuxConfig {
//!     public_url: "https://rise.example.com".parse().unwrap(),
//!     sealer: Arc::new(XChaChaSealer::new(&[7; 32], None).unwrap()),
//!     replay_cache: None,
//!     http: reqwest::Client::new(),
//! };
//! let app = router(Arc::new(instances), config, KeyStrategy::TwoSegment);
//! let _host = axum::Router::new().nest("/", app);
//! ```

mod model;
mod resolver;
mod router;
mod seal;

pub use model::*;
pub use resolver::*;
pub use router::*;
pub use seal::*;
