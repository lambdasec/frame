# The image tests/fixtures/sca/container/lang-image/ was recorded from (the files Frame reads, via
# docker export). Language packages: pip into /usr/local (no OS package owns them), Debian's own
# python3-urllib3 (dpkg owns it: left to Debian's advisories), an npm tree copied from a Node
# build stage, and a jar from Maven Central. tests/test_sca_container.py rebuilds it live.
FROM node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0 AS web
WORKDIR /app
RUN npm install --no-audit --no-fund lodash@4.17.20 express@4.17.1

FROM python:3.12-slim-bookworm@sha256:62ed8e07e544e8555c5d93748d5275015136b7f5c52b5e8679b4de339c3779d3
RUN apt-get update && apt-get install -y --no-install-recommends python3-urllib3 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir requests==2.25.0 urllib3==1.26.4 PyYAML==5.3.1 certifi==2026.10.23 chardet==3.0.4 idna==2.10
COPY --from=web /app/node_modules /app/node_modules
ADD https://repo1.maven.org/maven2/org/apache/commons/commons-text/1.9/commons-text-1.9.jar /app/lib/commons-text-1.9.jar
