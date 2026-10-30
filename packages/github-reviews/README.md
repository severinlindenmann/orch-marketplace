# GitHub checks

Tells a waiting follow-up when the checks of a pull request have finished
(`orch follow-up --on github-reviews.checks.finished:owner:repo:number`). Store a GitHub token with `orch addon login github-reviews`.

- A pull request with no check runs (a repo that only uses commit statuses) stays pending until the follow-up deadline.
- More than 300 check runs cannot be judged: the event counts as failed.
- A 403 from GitHub, including a rate limit, shows as a login problem.
