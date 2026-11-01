# DeepSeek Harness preview image

Pinned recipe for `ghcr.io/klorq/sandbox-dsh`. The package
`@deepseek-ai/dsh` is MIT-licensed; see the upstream package for its complete
dependency notices. The image is anonymous and contains no API keys.

Build and publish:

```sh
docker buildx build --platform linux/arm64 \
  -t ghcr.io/klorq/sandbox-dsh:0.2.1-rc.5 --push agents/dsh
```

The entrypoint binds the guest's concrete IPv4 address (the Klorq web profile
rejects wildcard bind addresses) and serves the browser UI on port 8080.
Expose it only on loopback through the sandbox port mapping.
