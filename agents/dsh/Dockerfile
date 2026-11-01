# Pinned DeepSeek Harness preview image. The image intentionally contains no
# credentials; API keys are supplied by the host broker at runtime.
FROM node:22@sha256:18a6d90fd60542269850c80ca03b29b1d9b14d6b221ac7ee8e35b0d33ef904bd

ARG DSH_VERSION=0.2.1-rc.5
ARG PNPM_VERSION=10.18.3

RUN npm install --global "@deepseek-ai/dsh@${DSH_VERSION}" "pnpm@${PNPM_VERSION}" \
 && npm cache clean --force

COPY entrypoint.sh /usr/local/bin/klorq-dsh-entrypoint
RUN chmod 0755 /usr/local/bin/klorq-dsh-entrypoint

USER node
WORKDIR /home/node
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/klorq-dsh-entrypoint"]
