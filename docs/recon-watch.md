# Recon watch

Watch state is persistent and local: profile, interval, last/next run, result, status, and error count. The foreground watcher checks that the program remains active, runs the existing recon engine, diffs inventory, and creates persistent Leads only for changes above the configured interest threshold. Passive is the default; recurring active profiles require explicit automation permission.
