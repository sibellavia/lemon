use async_trait::async_trait;
use hyper::http::header;
use std::sync::Arc;

use crate::{
    common,
    config::SecurityConfig,
    handlers::{BoxedBody, Handler},
};
use hyper::body::Incoming as IncomingBody;
use hyper::{Request, Response};

pub struct SecHeaders<H> {
    inner: H,
    cfg: Arc<SecurityConfig>,
    hsts_value: Option<header::HeaderValue>,
}

impl<H> SecHeaders<H> {
    pub fn new(inner: H, cfg: Arc<SecurityConfig>, is_https: bool) -> Self {
        let hsts_value = if is_https && cfg.add_default_headers != Some(false) {
            Some(common::build_hsts(&cfg))
        } else {
            None
        };
        Self {
            inner,
            cfg,
            hsts_value,
        }
    }
}

#[async_trait]
impl<H: Handler> Handler for SecHeaders<H> {
    async fn handle(&self, req: Request<IncomingBody>) -> anyhow::Result<Response<BoxedBody>> {
        let mut resp = self.inner.handle(req).await?;

        let hdrs = resp.headers_mut();

        // --- X-Content-Type-Options ---
        hdrs.entry(common::H_XCTO)
            .or_insert(common::V_NOSNIFF.clone());

        // --- X-Frame-Options / CSP frame-ancestors ---
        match self.cfg.frame_options.as_deref() {
            Some("SAMEORIGIN") => {
                hdrs.entry(common::H_XFO)
                    .or_insert(common::V_SAMEORIGIN.clone());
            }
            Some("NONE") => { /* caller disabled XFO */ }
            _ => {
                hdrs.entry(common::H_XFO).or_insert(common::V_DENY.clone());
            }
        }

        // --- Strict-Transport-Security ---
        if let Some(hsts_header_value) = &self.hsts_value {
            hdrs.entry(header::STRICT_TRANSPORT_SECURITY)
                .or_insert_with(|| hsts_header_value.clone());
        }

        Ok(resp)
    }
}
