# Databricks

Tells a waiting follow-up when a Databricks job run has finished (`orch follow-up --on databricks.run.finished:<run id>`).

Settings: paste only the workspace host, for example `https://adb-123.4.azuredatabricks.net`. An address with a path or a
query (an Azure `?o=<id>` link) is refused. Hosts must end in `.cloud.databricks.com`, `.azuredatabricks.net` or
`.gcp.databricks.com`. Store a Databricks token with `orch addon login databricks`.

A 401 or 403 shows as a login problem; a run that does not exist counts as failed.
