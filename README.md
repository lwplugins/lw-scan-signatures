# lw-scan-signatures

Community malware signatures for the **lw-scan** WordPress scanner.

This repository is a pure data source: every file under `signatures/**/*.yaml`
describes exactly one signature. The `scan-data-lwplugins-com` backend
(`internal/adapter/lwgit`) fetches this repo's tarball by commit SHA and
parses each YAML file with `lwgit.ParseYAML`.

## Signature schema

```yaml
id: lw:0001            # unique, must match ^lw:\d{4,}$
kind: regex             # regex | literal | md5 | sha256 | sql_like_regex
target: file_php        # file_php|file_js|file_html|file_code|file_any|db_post|db_option|db_trigger|htaccess|request
pattern: 'eval\s*\(\s*base64_decode'   # PCRE body, no leading/trailing "/", single-quoted YAML scalar
flags: i                 # optional PCRE modifiers (i s m x u ...); omit or "" if none
sql_like: null           # only used for kind: sql_like_regex
tier: infected           # infected | suspicious | info
category: obfuscation    # webshell backdoor dropper injector seo_spam redirect obfuscation uploader mailer defacement credential unknown
name: eval(base64_decode(...))
description: Classic one-liner decoder-eval dropper.
common_strings: []       # optional; leave [] and the backend derives them
tests:                   # mandatory, both non-empty
  match:
    - "<?php eval(base64_decode('aGVsbG8='));"
  no_match:
    - "<?php // eval() only appears in this comment"
```

Notes on `pattern` for `kind: regex` / `kind: sql_like_regex`:

- It is a raw PCRE **body**, without the surrounding `/.../` delimiters — the
  backend (and `.github/validate.php` in this repo) wraps it as
  `/`+pattern+`/`+flags before compiling.
- Write it as a single-quoted YAML scalar so backslashes stay literal.
- Every string in `tests.match` must match the compiled pattern; every string
  in `tests.no_match` must not. CI enforces this on every push and PR.
- `tier: suspicious` is for heuristics that can also fire on benign code;
  `tier: infected` is reserved for high-confidence malware patterns;
  `tier: info` is for cosmetic/non-executable markers (e.g. defacement text).

## Layout

```
lw-scan-signatures/
├── README.md
├── signatures/
│   ├── backdoor/0001.yaml
│   ├── obfuscation/0002.yaml
│   └── ...                       # one file per signature, grouped by category,
│                                  # filename = the signature's numeric id
└── .github/
    ├── validate.php              # self-contained PHP validator (no Composer deps)
    └── workflows/validate.yml    # CI: runs validate.php on every push/PR
```

## Validating locally

The validator is a single dependency-free PHP script. Run it with any PHP 8.x
CLI from the repo root:

```bash
php .github/validate.php
```

It checks, for every `signatures/**/*.yaml` file:

- the file parses under this repo's YAML subset
- `id` matches `^lw:\d{4,}$` and is unique across the whole repo
- `kind`, `target`, `tier`, `category` are all valid enum values
- `pattern` is non-empty
- `tests.match` and `tests.no_match` are both non-empty
- for `kind: regex` / `kind: sql_like_regex`: the pattern compiles as PHP
  PCRE (`/pattern/flags`), every `tests.match` string matches it, and every
  `tests.no_match` string does not

It exits non-zero and prints every violation if anything fails, and prints
`OK: N signatures` on success. The same script runs in CI
(`.github/workflows/validate.yml`) via `shivammathur/setup-php`.

## Contributing a signature

1. Pick the right category directory under `signatures/` (create one if a
   new category is genuinely needed) and add `NNNN.yaml` using the next free
   4-digit id.
2. Write at least one realistic `tests.match` string and one realistic
   `tests.no_match` string (something that looks similar but is benign).
3. Run `php .github/validate.php` locally and fix anything it flags.
4. Open a PR — CI re-runs the same validator.
