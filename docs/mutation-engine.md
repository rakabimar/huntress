# Bounded mutation engine

`MutationPlan` requires maximum requests, parameters, and candidates per parameter. It generates compact type-aware candidates from observed values and executes one field at a time by default through request replay and the Broker. Results are automatically clustered with `ResponseComparator`; anomalies are observations, not findings. Plans are capped at 100 requests and do not use large generic payload lists.
