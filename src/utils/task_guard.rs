//! Stop a helper task when its owner goes away: aborting a task does not abort the tasks it
//! spawned, so a connection's reader task is held in one of these.
//!
//! The same holds for a task that is *awaited* rather than detached: a parent that awaits a
//! child's `JoinHandle` (directly or inside a `select!`) and is then aborted drops the handle,
//! and dropping a `JoinHandle` detaches the child — it keeps running. Hold the handle in one of
//! these and await `guard.0` instead, so aborting the parent ends the child too.

pub struct AbortOnDrop<T = ()>(pub tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
