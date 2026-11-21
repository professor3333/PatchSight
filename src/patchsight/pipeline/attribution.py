"""The attribution and licence every published copy of the database carries.

CC BY 4.0 (rule 14) asks for credit to the sources and a statement of what was changed. The
GitHub release notes and the Hugging Face dataset card use this same text.
"""

ATTRIBUTION = """## Attribution and licence

Advisory identifiers and affected-package data come from [OSV.dev](https://osv.dev), which \
aggregates the [GitHub Advisory Database](https://github.com/github/advisory-database) and the \
[PyPA Advisory Database](https://github.com/pypa/advisory-database). All three are licensed \
CC BY 4.0.

**Changes made:** PatchSight resolved each advisory's fix commit on GitHub, mapped the changed \
lines to function names with tree-sitter, and, where shown, had language models choose the \
vulnerable ones. It stores those names with file paths, line ranges and commit SHAs. No \
third-party source code is included.

**Licence:** the PatchSight symbol database is licensed under \
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). If you share it, or data derived from \
it, credit "PatchSight symbol database" with the release, keep the attribution above, and say \
what you changed.
"""
