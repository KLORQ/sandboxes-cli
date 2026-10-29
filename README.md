# sandboxes-cli

Status: pre-alpha.

Command-line and terminal client. Uses sandboxes-go-sdk; does not import daemon
internals.

## Commands

```sh
sbx --socket "$HOME/.sandboxes/sandboxesd.sock" create dev
sbx --socket "$HOME/.sandboxes/sandboxesd.sock" ls
sbx --socket "$HOME/.sandboxes/sandboxesd.sock" get <id>
sbx --socket "$HOME/.sandboxes/sandboxesd.sock" start <id>
sbx --socket "$HOME/.sandboxes/sandboxesd.sock" stop <id>
sbx --socket "$HOME/.sandboxes/sandboxesd.sock" rm [--force] <id>
sbx --socket "$HOME/.sandboxes/sandboxesd.sock" wait <operation-id>
```

`SANDBOXES_SOCKET` can replace the `--socket` flag. The installed binary is `sbx`; `sandboxes` is only the repository name.

## Development

Requires Go 1.27.

```sh
make test
make build
```
