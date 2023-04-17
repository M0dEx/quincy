use anyhow::Result;
use std::time::Duration;
use tokio::task::{AbortHandle, JoinError, JoinHandle};
use tokio::time::sleep;
use tokio::try_join;

/// Aborts a task after a specified duration.
///
/// ### Arguments
/// - `abort_handle` - the abort handle of the task to be aborted
/// - `duration` - the duration after which the task should be aborted
async fn abort_after(abort_handle: AbortHandle, duration: Duration) -> Result<(), JoinError> {
    sleep(duration).await;
    abort_handle.abort();

    Ok(())
}

/// Joins a task or aborts it after a specified duration.
///
/// ### Arguments
/// - `task` - the task to be joined or aborted
/// - `duration` - the duration after which the task should be aborted
///
/// ### Returns
/// - `R` - the result of the task
pub async fn join_or_abort_task<R>(task: JoinHandle<R>, duration: Duration) -> Option<R> {
    let abort_handle = task.abort_handle();

    let (_, result) = try_join!(abort_after(abort_handle, duration), task).ok()?;

    Some(result)
}
