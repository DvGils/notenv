# Installation

## Requirements

- **Linux, macOS, or Windows.** On Linux, notenv also caches your key and secrets in RAM for a
  faster, prompt-free workflow.
- **For cloud remotes only:** [rclone](https://rclone.org/install/) on your `PATH` and a storage
  remote you control (Backblaze B2, S3, and so on; notenv can create the remote for you during
  setup). A local vault needs neither.

## Install notenv

=== "uv / pipx / pip"

    The PyPI package carries the same prebuilt, statically linked binary the GitHub release
    ships, for all six platform/architecture pairs; no Python code runs.

    ```sh
    uv tool install notenv      # or: pipx install notenv, or: pip install notenv
    ```

=== "Go"

    ```sh
    go install github.com/DvGils/notenv/cmd/notenv@latest
    ```

=== "Prebuilt binary"

    Download a build for Linux, macOS, or Windows (amd64 / arm64) from the
    [Releases](https://github.com/DvGils/notenv/releases) page, extract `notenv`, and put it on
    your `PATH`.

    Releases are reproducible, signed with [cosign](https://github.com/sigstore/cosign) (keyless),
    and carry SLSA build provenance. To verify a download:

    ```sh
    cosign verify-blob \
      --bundle checksums.txt.bundle \
      --certificate-identity-regexp '^https://github\.com/DvGils/notenv/\.github/workflows/release\.yml@refs/tags/v' \
      --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
      checksums.txt
    sha256sum -c checksums.txt --ignore-missing      # then check your archive's hash
    ```

=== "From source"

    ```sh
    git clone https://github.com/DvGils/notenv
    cd notenv
    make build       # compile ./notenv
    make test        # run the test suite
    make install     # install into $(go env GOPATH)/bin
    ```

    Releases are produced with [GoReleaser](https://goreleaser.com); `make snapshot` builds the full
    set of release artifacts locally without publishing.

## Verify the install

```sh
notenv --version      # prints the version, commit, and build date
```

Next: set up a machine and run your first command in the [quick start](quick-start.md).
