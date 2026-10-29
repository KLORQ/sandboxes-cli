# sandboxes-cli

Status: pre-alpha.

Command-line and terminal client. Uses sandboxes-go-sdk; does not import daemon
internals.

## Commands

```sh
sandboxes --socket "$HOME/.sandboxes/sandboxesd.sock" create dev
sandboxes --socket "$HOME/.sandboxes/sandboxesd.sock" ls
sandboxes --socket "$HOME/.sandboxes/sandboxesd.sock" get <id>
sandboxes --socket "$HOME/.sandboxes/sandboxesd.sock" start <id>
sandboxes --socket "$HOME/.sandboxes/sandboxesd.sock" stop <id>
sandboxes --socket "$HOME/.sandboxes/sandboxesd.sock" rm [--force] <id>
sandboxes --socket "$HOME/.sandboxes/sandboxesd.sock" wait <operation-id>
```

`SANDBOXES_SOCKET` can replace the `--socket` flag.

## Development

Requires Go 1.27.

```sh
make test
make build
```
