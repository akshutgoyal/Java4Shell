# syntax=docker/dockerfile:1.7
#
# Java4Shell (CVE-2026-114938) lab.
#
# The base image is deliberately a pre-fix OpenJDK 21 build (Temurin
# 21.0.13+9, published 2026-10-20).  It is pinned by digest so the tag
# being re-pushed with the fixed JDK cannot silently change the lab.
#
# Intel SDE is downloaded from Intel's official mirror and verified against
# Intel's published SHA256.  SDE lets us execute the real AVX-512 VBMI stub
# on hosts without AVX-512, by spoofing the CPUID of an Ice Lake server CPU.

FROM eclipse-temurin:21.0.13_9-jdk-noble@sha256:a2e61ec9e2e4d5c7aa885412400319f9299abe4d8189f42ec3bec48708c576a6

ARG SDE_URL=https://downloadmirror.intel.com/924984/sde-external-10.13.1-2026-07-28-lin.tar.xz
ARG SDE_SHA256=94E97D623FEC54385686E1E7BA65EBC9941748C05EE451423948334892BF2B50

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "$SDE_URL" -o /tmp/sde.tar.xz \
 && echo "$SDE_SHA256  /tmp/sde.tar.xz" | sha256sum -c - \
 && mkdir -p /opt/sde \
 && tar -xJf /tmp/sde.tar.xz -C /opt/sde --strip-components=1 \
 && rm -f /tmp/sde.tar.xz

WORKDIR /opt/lab

COPY poc ./poc
RUN javac -nowarn -d classes poc/*.java

COPY scripts/run-lab.sh /usr/local/bin/run-lab
RUN chmod +x /usr/local/bin/run-lab

# auto: native JVM on AVX-512 hosts, Intel SDE everywhere else.
ENV LAB_MODE=auto
ENV LAB_WARMUP=1000

ENTRYPOINT ["/usr/local/bin/run-lab"]
CMD ["all"]
