# Secret-check fixtures

These fixture directories are source inputs for the `QC.SECRETS.TRACKED` adapter. They are not
real Git repositories and contain no usable credential. A verifier should copy one directory into
a disposable Git checkout, commit it, and run:

```sh
python3 adapters/deterministic_checks.py \
  --repository-root <checkout> \
  --catalog policies/check-catalog.json \
  --check QC.SECRETS.TRACKED
```

`passing-project/` must return `PASS`. `failing-project/` contains a deliberately fake private-key
marker and must return `FAIL` with a bounded finding for that path. A dirty checkout, malformed
catalog, unsupported check, Git failure, or output over the adapter limits must return `BLOCKED`.
