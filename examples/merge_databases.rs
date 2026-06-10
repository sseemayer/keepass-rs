//! Example for merging two versions of the same KeePass database.
//!
//! `Database::merge` performs a two-way, newest-wins merge and returns a
//! [`MergeLog`](keepass::db::merge::MergeLog).
//!
//! Three-way merging is being added in:
//! <https://github.com/sseemayer/keepass-rs/pull/342>.
//!
//! This example should be extended to cover it once merged.
use keepass::db::merge::{MergeError, MergeEvent, MergeEventTarget, MergeEventType, MergeLog};
use keepass::db::{fields, Database};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start from a shared database and take a second copy to diverge from it.
    let mut destination = Database::new();
    let shared_entry_id = destination
        .root_mut()
        .add_entry()
        .edit_tracking(|e| e.set_unprotected(fields::TITLE, "shared entry"))
        .id();
    let mut source = destination.clone();

    // Add an entry on the source side that the destination has not seen.
    source
        .root_mut()
        .add_entry()
        .edit_tracking(|e| e.set_unprotected(fields::TITLE, "added on source"));

    // Edit shared field, but later for destination (destination wins).
    // Times::now() has second precision, so sleep 1 s between the two edits to
    // guarantee destination's timestamp is strictly greater than source's.
    if let Some(mut source_shared_entry) = source.root_mut().entry_mut(shared_entry_id) {
        source_shared_entry.edit_tracking(|e| e.set_unprotected(fields::USERNAME, "LosingUser"));
    }
    std::thread::sleep(std::time::Duration::from_secs(1));
    if let Some(mut destination_shared_entry) = destination.root_mut().entry_mut(shared_entry_id) {
        destination_shared_entry.edit_tracking(|e| e.set_unprotected(fields::USERNAME, "WinningUser"));
    }

    // Use `MergeLog` / `MergeError` to inspect the merge.
    let log: MergeLog = {
        let result: Result<MergeLog, MergeError> = destination.merge(&source);
        result?
    };

    // Report any issues (e.g. due to lack of tracking)
    if log.warnings.is_empty() {
        println!("Merge completed with no issues.");
    } else {
        println!("Merge completed with {} warning(s):", log.warnings.len());
        for warning in &log.warnings {
            println!("  - {warning}");
        }
    }

    // Categorise each change by matching on the public event enums.
    println!("Applied {} change(s):", log.events.len());
    for MergeEvent { target, event_type } in &log.events {
        let kind = match event_type {
            MergeEventType::Created => "created",
            MergeEventType::Deleted => "deleted",
            MergeEventType::LocationUpdated => "moved",
            MergeEventType::Updated => "updated",
            // `MergeEventType` is `#[non_exhaustive]`.
            _ => "changed",
        };
        let what = match target {
            MergeEventTarget::Entry(id) => format!("entry {id}"),
            MergeEventTarget::Group(id) => format!("group {id}"),
            MergeEventTarget::Icon(id) => format!("icon {id}"),
            // `MergeEventTarget` is `#[non_exhaustive]`.
            _ => "object".to_string(),
        };
        println!("  - {kind} {what}");
    }

    // Print each entry in the merged database.
    println!("\nEntries in merged database:");
    for entry in destination.root().entries() {
        let title = entry.get(fields::TITLE).unwrap_or("<no title>");
        let username = entry.get(fields::USERNAME).unwrap_or("<no username>");
        println!("  title={title:?}  username={username:?}");
    }

    Ok(())
}
