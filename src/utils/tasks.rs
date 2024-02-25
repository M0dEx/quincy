use anyhow::Result;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use tokio::task::JoinHandle;

/// Aborts a given task.
///
/// ### Arguments
/// - `task` - the task to be joined or aborted
///
/// ### Returns
/// - `R` - the result of the task
pub async fn abort_task<R>(task: &mut JoinHandle<R>) -> Result<R> {
    task.abort();

    Ok(task.await?)
}

/// Joins all tasks in a FuturesUnordered or aborts them after a specified duration.
pub async fn abort_all<R>(mut tasks: FuturesUnordered<JoinHandle<R>>) -> Result<()> {
    let mut aborted_tasks = tasks
        .iter_mut()
        .map(|handle| abort_task(handle))
        .collect::<FuturesUnordered<_>>();

    while (aborted_tasks.next().await).is_some() {}

    Ok(())
}
