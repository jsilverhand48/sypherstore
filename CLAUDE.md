When working in this repo, use Serena's symbol tools (get_symbols_overview,
find_symbol, find_referencing_symbols) to navigate. Do not read whole files
or symbol bodies unless the task requires the implementation. Prefer
symbol-level edits (replace_symbol_body, rename_symbol) over full-file rewrites.

## DO NOT
- Read any of the files in docs/ unless prompted to do so
- Commit any changes

## Documentation
Any time code is changed anywhere, make sure to update the documentation within the file containing the changed code as well as the README.md file for the respective directory.

## Testing
- Run only the specific test(s) relevant to the change, never the full suite unless I explicitly ask.
- Only write test fiels to claude_tests/
