# Import an existing `.env`

If you already have a `.env` file, `notenv namespace import` encrypts every value and declares every key in
one command, so you do not retype anything.

```sh
notenv namespace import .env && rm .env
```

The whole file is parsed and validated before anything is written, and all values land in a single
recorded write: an import either fully happens or it does not. The file itself is never modified;
once the import succeeds, deleting it is safe and the point.

## Preview first

`--dry-run` parses and validates without writing, showing what would be imported (names, never
values):

```sh
notenv namespace import .env --dry-run
```

## What gets imported

- Every valid `KEY=value` assignment becomes an encrypted secret, declared in `notenv.toml`.
- Duplicate keys resolve last-wins.
- Empty values are skipped (`notenv secret set` refuses those, so import does too).
- Existing descriptions on keys are preserved; an import overwrites values, not what the keys mean.

## Accepted dotenv syntax

notenv parses a documented, deliberately small subset of dotenv syntax. An importer for secrets must
never guess, so anything outside this subset fails the parse with its line number rather than being
interpreted:

- Blank lines and full-line `#` comments are skipped. An unquoted value may carry a trailing comment
  when whitespace precedes the `#`.
- An optional `export ` prefix is dropped.
- Unquoted values are trimmed of surrounding whitespace.
- Single-quoted values are literal. Double-quoted values understand the `\n`, `\t`, `\"`, and `\\`
  escapes. Both kinds may span multiple lines.
- There is no variable expansion of any kind. A secrets file is not a shell script, and silently
  expanding `$X` would corrupt real values.

!!! tip "Multiline or piped values"

    To set a single multiline value (a PEM key, a JSON blob) outside of an import, use
    `notenv secret set KEY --stdin` and pipe the value in.
