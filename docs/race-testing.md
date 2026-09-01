# Race testing

`ConcurrentRequestPlan` supports bounded parallel and application-thread barrier modes under `race_test` policy, shared rate/concurrency limits, and explicit request counts. Barrier mode synchronizes worker start; it is not single-packet or last-byte synchronization. Results include every request, response clusters, timing metadata where captured, and an optional post-condition read. Response variation alone is not impact.
