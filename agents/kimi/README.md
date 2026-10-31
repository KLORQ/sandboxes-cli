# Kimi agent image

Build:

```sh
docker buildx build --platform linux/arm64 \
  -t ghcr.io/klorq/sandbox-kimi:0.43.0 -f agents/kimi/Dockerfile .
```

The image pins Python 3.13 slim and `kimi-cli==0.43`. Publish the digest in the
release notes before making it the default image.
