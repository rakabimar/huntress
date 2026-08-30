# Session lifecycle methodology

Inventory credential classes and events. Capture a pre-event credential fingerprint/AuthContext, perform exactly one login/elevation/logout/password/MFA/role/device event, then replay the prior credential against one protected read. Compare authenticated identity and capability, not token parsing.

Fixation tests compare pre- and post-login/elevation identifiers and predecessor validity. Refresh tests track family relationships and reuse behavior. Timeout tests need bounded controlled clocks or short configured fixtures; do not wait or flood production.
