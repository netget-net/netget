//! The real-model eval harness.
//!
//! # Why this is not like any other test here
//!
//! Every other suite in this repository drives a **mock** model whose answers
//! the test author wrote. That proves the plumbing carries a correct answer from
//! the model to the wire. It proves nothing about whether a real model, reading
//! a protocol's actual action descriptions and parameter docs, can *produce* one
//! — and "an LLM drives the protocol" is the entire premise of NetGet.
//!
//! So: a set of canonical operator instructions in plain English, run against a
//! real local model, driven with a **real third-party client binary**, scored on
//! what that client observed.
//!
//! # The shape of one case
//!
//! ```text
//!   instruction (plain English, names no action)
//!        │
//!        ├─► netget --server <proto> --port N "<instruction>"   (no model call)
//!        │
//!        └─► dig / curl / redis-cli / psql / …  ──► observable result
//!                                                        │
//!                          netget's own log ─────────────┴──► verdict + diagnosis
//! ```
//!
//! `LiveRequestTest` (`tests/helpers/llm_live.rs`) starts the server
//! deterministically, so the **only** unpredictable step in a run is the model
//! answering the network event. That is deliberate: setup correctness is a
//! different question with its own tests, and chaining the two would make every
//! failure ambiguous.
//!
//! # What comes out
//!
//! `eval-results/latest.json` and `eval-results/EVAL_RESULTS.md`, regenerated together. The
//! pass rate is the headline; the ranked **failure modes**, each carrying the
//! model's actual output, are the useful part — an action description that
//! misleads a model is a defect in the description, and this is the only thing
//! in the tree that can see one.
//!
//! # This must never gate a PR
//!
//! It costs real model time and it is not deterministic. `tests/eval.rs` skips
//! unless `NETGET_USE_OLLAMA=1`, and a low score is reported, never asserted.
//! `./run-eval.sh` and `.github/workflows/nightly-eval.yml` are how it runs.

pub mod case;
pub mod classify;
pub mod probe;
pub mod probe_check;
pub mod report;
pub mod runner;
pub mod scoring;
pub mod suites;
