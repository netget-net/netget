#[cfg(unix)]
mod certificate_cache_bound_test;
#[cfg(unix)]
mod connection_bounds_test;
#[cfg(unix)]
mod e2e_test;
#[cfg(unix)]
mod llm_failure_test;

// `test.rs` is the functional suite: it stands up real HTTP/HTTPS target servers and drives
// traffic through the proxy with `reqwest`. `e2e_test.rs` only checks that the server starts.
#[cfg(unix)]
mod test;

#[cfg(unix)]
mod status_range_test;

#[cfg(unix)]
mod header_injection_test;

#[cfg(unix)]
mod mitm_dial_order_test;
