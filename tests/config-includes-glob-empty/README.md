# config-includes-glob-empty

Verifies that a glob pattern in an `include:` directive that matches no files
is not an error (Redmine #8427). This is the drop-in `conf.d/` use case, where
the directory may be empty.

The setup step creates an empty `conf.d/` directory in the output directory and
copies `empty.yaml` next to it. Suricata is run with `--dump-config` against
that copy, which includes `conf.d/*.yaml`.

The test checks that:

- Suricata exits successfully,
- the keys defined before and after the include are present in the dumped
  config, so loading continued after the empty include, and
- a "No files match include pattern" warning is logged.

Like `config-includes-glob-order`, the test is skipped on builds without glob
support in `include:` and on builds without `glob(3)`, notably Windows.
