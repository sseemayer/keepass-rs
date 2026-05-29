//! Regression test: with the `_merge` feature enabled, the merge result
//! types must be nameable AND usable from outside the crate. Without
//! `pub mod merge` in `src/db/mod.rs`, `Database::merge` is callable but
//! its return types (`MergeLog` / `MergeError` / `MergeEvent` /
//! `MergeEventType` / `MergeEventTarget`) live in a private module, so a
//! downstream crate cannot name them to inspect the log a merge produces.
#![cfg(feature = "_merge")]
#![forbid(unsafe_code)]
#![allow(missing_docs, clippy::expect_used)]

use keepass::db::merge::{MergeError, MergeEvent, MergeEventTarget, MergeEventType, MergeLog};
use keepass::db::{fields, Database};

/// Mirror what a downstream consumer does: merge two versions of a
/// database, then inspect the returned `MergeLog` by matching on the
/// public event enums. This proves the types are reachable and exercises
/// them at runtime, rather than just compiling.
#[test]
fn merge_log_is_inspectable_downstream() {
    let mut destination = Database::new();
    let mut source = destination.clone();

    // A new entry on the source side that the destination has not seen.
    source
        .root_mut()
        .add_entry()
        .edit_tracking(|e| e.set_unprotected(fields::TITLE, "added on source"));

    // The whole point of the re-export: name `MergeLog` / `MergeError`
    // as the return type from outside the crate.
    let result: Result<MergeLog, MergeError> = destination.merge(&source);
    let log = result.expect("merging a superset source should succeed");

    // The new entry produces exactly one event, which a consumer can
    // categorise by matching the public enums.
    assert!(log.warnings.is_empty());
    let event: &MergeEvent = log.events.first().expect("one merge event");
    assert!(matches!(event.event_type, MergeEventType::Created));
    assert!(matches!(event.target, MergeEventTarget::Entry(_)));

    // Exhaustively name the remaining variants so this test stops
    // compiling if any becomes unreachable. The enums are
    // `#[non_exhaustive]`, so each match needs a wildcard arm.
    match event.event_type {
        MergeEventType::Created
        | MergeEventType::Deleted
        | MergeEventType::LocationUpdated
        | MergeEventType::Updated => {}
        _ => {}
    }
    match event.target {
        MergeEventTarget::Entry(_) | MergeEventTarget::Group(_) | MergeEventTarget::Icon(_) => {}
        _ => {}
    }
}
