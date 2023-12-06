use anyhow::Result;
use futures::stream::FuturesUnordered;
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
pub async fn join_or_abort_task<R>(task: &mut JoinHandle<R>, duration: Duration) -> Result<R> {
    let abort_handle = task.abort_handle();

    let (_, result) = try_join!(abort_after(abort_handle, duration), task)?;

    Ok(result)
}

/// Joins all tasks in a FuturesUnordered or aborts them after a specified duration.
pub async fn join_or_abort_all<R>(
    mut tasks: FuturesUnordered<JoinHandle<R>>,
    duration: Duration,
) -> Result<()> {
    for task in tasks.iter_mut() {
        join_or_abort_task(task, duration).await?;
    }

    Ok(())
}
