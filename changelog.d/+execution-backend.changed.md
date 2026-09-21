**Internal: script-step execution now runs through a pluggable execution
backend seam owned by the workflow engine** — a stdlib-only
`conductor.execution` contract (`RunnerBackend` protocol, data-shaped
`CommandResult`/`StartError`, run-scoped `WorkspaceLease`) with a local
subprocess reference implementation (`LocalRunnerBackend`). The root engine
prepares the run's workspace lease in `run()`/`resume()` and finalizes it in
the matching `finally` with the run's outcome (succeeded/failed/cancelled);
sub-workflows inherit the root run's backend and lease, so one run owns
exactly one lease. **No behavior change**: rendered commands, environment
handling, timeouts, error messages, and exit-code routing are unchanged; the
only internal difference is that the script child process is now always
killed and reaped when the run task is cancelled.
