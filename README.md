# sandboxes-cli

Status: pre-alpha.

Command-line and terminal client. Uses sandboxes-go-sdk; does not import daemon
internals.

## Commands

```sh
ksbx --socket "$HOME/.sandboxes/sandboxesd.sock" create dev
ksbx --socket "$HOME/.sandboxes/sandboxesd.sock" ls
ksbx --socket "$HOME/.sandboxes/sandboxesd.sock" get <id>
ksbx --socket "$HOME/.sandboxes/sandboxesd.sock" start <id>
ksbx --socket "$HOME/.sandboxes/sandboxesd.sock" stop <id>
ksbx --socket "$HOME/.sandboxes/sandboxesd.sock" rm [--force] <id>
ksbx --socket "$HOME/.sandboxes/sandboxesd.sock" wait <operation-id>
```

`SANDBOXES_SOCKET` can replace the `--socket` flag. The installed binary is `ksbx`; `sandboxes` is only the repository name. `sbx` remains an optional compatibility alias only when the Docker CLI is not installed.

## Development

Requires Go 1.27.

```sh
make test
make build
```
