# Expert guide: server template injection

## Mental model
Trace input→stored/transformed data→template source construction→engine/parser→context/sandbox→rendered output or side effect. Supplying data to a fixed template is different from concatenating attacker data into the template program.

## Attack surface and methodology
Review preview/theme/template editors, email/PDF/document rendering, error pages, CMS fields, notification formats, and user-selectable template names. Identify server versus client evaluation and likely engine from source/errors. Use one harmless deterministic expression with paired literal control; vary only enough to disambiguate engine/application computation. Stop at expression evaluation.

Decision tree: literal reflection/client-side evaluation → reject SSTI; coincidental result not tracking a second expression → reject; deterministic server expression evaluation → support primitive; file/process access escalation is a new high-risk hypothesis requiring isolated/approved validation. Production RCE, file reads, and resource exhaustion are DENY/ASK as classified.
