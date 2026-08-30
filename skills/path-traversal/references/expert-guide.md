# Expert guide: filesystem containment

## Mental model
Trace input→decoding layers→path join/normalize/canonicalize→symlink resolution→root containment check→filesystem operation. Read, write, delete, include, and archive extraction have different impact. The check and operation must use the same canonical path/root and resist TOCTOU.

## Attack surface and methodology
Review download/export/template/language/image paths, user filenames, backup/import, archive members, storage keys, plugin/theme files, static serving, and Windows/Unix separators/absolute paths. Infer decoding/normalization from framework/source, then use one harmless known fixture file or marker. Do not enumerate sensitive files.

Decision tree: payload normalized by proxy before app and serves expected route → reject; filename reflected only → no traversal; canonical path remains inside root → control; known harmless file outside intended root read/written → support. Archive extraction and write/delete are stateful/risk-sensitive; production sensitive-file reads are DENY.
