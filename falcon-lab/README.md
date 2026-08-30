# Falcon lab

`falcon-lab` runs Maghemite integration topologies under Falcon. A topology
defines the VM graph, while a scenario configures and tests that topology. The
topologies use prebuilt Falcon base images for Helios, Debian/FRR, cEOS,
Junos/cRPD, and BIRD 2 nodes, plus a per-run `cargo-bay/` 9p share for binaries
and runtime configuration.

## Topologies and scenarios

Supported topology/scenario pairs are:

```text
mgd-duo  bare
mgd-duo  bgp-unnumbered
interop  bare
interop  bgp-unnumbered
interop  bfd-static-routing
interop-3-link  bare
interop-3-link  bgp-md5
```

`mgd-duo` connects two Maghemite nodes. `interop` connects a Maghemite DUT to
FRR, Arista EOS, Juniper cRPD, a second Maghemite node, and BIRD 2 (AS 48,
router ID 1.2.3.3). BIRD is appended on DUT port `qsfp4`, preserving existing
ports. `interop-3-link` gives each peer three links; BIRD uses `qsfp12`–`qsfp14`
and the existing Maghemite peer remains on `qsfp9`–`qsfp11`.

`interop bgp-unnumbered` checks five imported/selected paths and five ECMP
targets for both `1.2.3.0/24` and `fd99::/64`, plus each peer's imports of DUT
prefixes `4.5.6.0/24` and `fdee::/64`. BIRD uses TCP MD5 on every session;
the other peers' authentication settings are unchanged.

`interop-3-link bgp-md5` retains the passive-DUT/active-Maghemite numbered
IPv4 accepted-socket regression on `qsfp9` (including TCP port roles and
13 seconds without FSM transitions). It then tests all three BIRD unnumbered
links with TCP MD5, bidirectional dual-stack prefix exchange, three-way DUT
ECMP, and another 13-second stability observation. It does not substitute
numbered or unauthenticated BIRD sessions.

`interop bfd-static-routing` includes BIRD's IPv4 and IPv6 BFD sessions
(`10.0.4.1`/`.2`, `fd00:5::1`/`::2`) with 1-second intervals and multiplier 3.
Failure/recovery phases verify each peer, BIRD as the last surviving path,
all peers down, and all five peers restored, including peer-side Up checks.

Run and cleanup commands both take a topology and scenario:

```sh
pfexec target/release/falcon-lab run interop bgp-unnumbered --no-cleanup
pfexec target/release/falcon-lab cleanup interop bgp-unnumbered
```

The `bare` scenarios launch their topology without applying protocol
configuration.

## BIRD image and launch contract

The node image is `voxel-bird2`, fetched and imported by Falcon's **normal
base-image preflight**, just like the other images, from:

```text
https://oxide-falcon-assets.s3.us-west-2.amazonaws.com/voxel-bird2_0.raw.xz
```

No custom downloader, manual image import, or launch-time package installation
is needed. The Debian image must already contain BIRD 2, `birdc`, `iproute2`,
`bird.service`, and `/opt/oxide/voxel-init` with its `bird` subcommand.
Falcon's normal setup stays enabled, with an explicit Linux 9p mount.

Data NICs are resolved from `ip -j link` by the MACs assigned in the topology,
not guessed from Debian interface order. After IPv6 DAD, falcon-lab reads both
ends' actual link-local addresses, stages `cargo-bay/bird-bird.conf`, and runs
`voxel-init bird --config /opt/cargo-bay/bird-bird.conf`. It verifies both command
success and `/run/voxel-bird-ready`, since Falcon exec alone only reports
transport success. Configuration is explicitly copied/applied after launch;
there is no guest auto-apply service and stale staged files are not consumed.

Each link gets a scoped BGP protocol and a data-only RAdv interface. The
shared test password `falcon-bgp-md5-test-key` is configured on **both** BIRD
and DUT. IPv4 uses extended IPv6 next hops. Export policies allow only the
fixture static prefixes with IGP origin, never management/default routes or
reflected DUT routes. BIRD import checks query its RIB by prefix and BGP
protocol; no kernel-route installation is assumed on BIRD.

Failure diagnostics include the baked version marker, BIRD protocol/routes/BFD
state, Linux networking, and the BIRD journal. BIRD is restarted before normal
failure diagnostics, just as the other peer daemons are restored.

For parser-only validation, export the exact single-link, three-link, and
BFD configs:

```sh
BIRD_CONFIG_DIR=/tmp/bird-configs \
  cargo test -p falcon-lab export_parser_fixtures --locked
```

The config/CLI-format tests also run without Falcon's illumos linker libraries
(from the repository root, including on macOS):

```sh
rustc --edition 2024 --test falcon-lab/src/bird/config.rs -o /tmp/bird-config-tests
BIRD_CONFIG_DIR=/tmp/bird-configs /tmp/bird-config-tests
```

On Linux, validate each with
`bird -p -c <file>`. This does not replace running the Falcon scenarios on an
illumos host with the baked image.

## Runtime cargo-bay contents

Before running any topology, `cargo-bay/` must contain:

- `mgd` and `ddmd`, staged by local test setup or the Buildomat job.

The interop topology additionally requires:

- `falcon-juniper-license.key`, a Juniper license file. This file is a secret:
  do not commit it, print it, include it in diagnostics, or pass its contents in
  command-line arguments.

`falcon-lab` writes non-secret Junos topology config as
`cargo-bay/<node>-junos.set`. The staged file is a complete non-interactive
Junos CLI input file: it starts with `configure`, contains `set ...` commands,
and ends with `commit`.

Junos topology config is per-run state. `falcon-lab` removes stale
`cargo-bay/*-junos.set` files before launching or cleaning up an interop
topology so the guest-side apply service cannot consume configuration left by
an earlier topology. Do not put persistent hand-written Junos config in files
matching that pattern.

## Junos license source and connectivity assumptions

CI fetches the Juniper license from:

```text
http://catacomb.eng.oxide.computer:12346/falcon/jl
```

That endpoint is reachable only from appropriate Oxide networks, such as the
corporate network/VPN or CI runners with catacomb access. Developer machines or
Falcon guests outside that network should not be expected to resolve or reach
it.

The division of ownership is:

1. The CI runner or developer fetches the license and places it at
   `cargo-bay/falcon-juniper-license.key` with restrictive permissions.
2. `falcon-lab` verifies that the file exists and stages non-secret topology
   config.
3. The Junos guest consumes the file by path after mounting `cargo-bay`; the
   license contents are never passed through falcon-lab logs or command-line
   arguments.

For local runs from a machine that can reach catacomb:

```sh
mkdir -p cargo-bay
curl -sSfL --retry 10 --retry-all-errors \
  -o cargo-bay/falcon-juniper-license.key \
  http://catacomb.eng.oxide.computer:12346/falcon/jl
chmod 0600 cargo-bay/falcon-juniper-license.key
```

## Junos image assumptions

The Falcon image named `junos-23.2` is expected to be built by the experimental
`voxel-image` tooling from the
[`oxidecomputer/voxel`](https://github.com/oxidecomputer/voxel) repository. The
portable artifact is uploaded alongside other Falcon assets as:

```text
https://oxide-falcon-assets.s3.us-west-2.amazonaws.com/junos-23.2_0.raw.xz
```

The image must already contain Docker and the Juniper cRPD image. It must not
contain a license or topology-specific routing config.

The image is also expected to contain these guest-side systemd services and
helpers:

- `voxel-crpd.service`: starts the `crpd1` container and attaches the data
  interfaces.
- `falcon-cargo-bay.service`: mounts the Falcon 9p share at `/opt/cargo-bay`.
- `falcon-junos-apply.service`: waits for
  `/opt/cargo-bay/falcon-juniper-license.key` and a non-empty
  `/opt/cargo-bay/*-junos.set`, then stages them under `/var/run/juniper/`,
  installs the license, and runs `cli -f /config/falcon-lab/topology.set` inside
  the cRPD container.

The apply service writes non-secret status/debug files:

- `/run/falcon-junos-apply.status`
- `/var/run/juniper/falcon-lab/apply.out`

Falcon-lab diagnostics may collect those files, but must not collect license
contents or unredacted logs/configuration that can include the license.

## Building and publishing the Junos image

On an illumos/Falcon-capable builder with `voxel` checked out:

```sh
cd ~/git/voxel
FALCON_DATASET=DATA/falcon \
  CAPTURE_MODE=zfs \
  IMAGE_NAME=junos-23.2 \
  ./voxel-image/build-junos.sh 23.2R1.13
```

`CAPTURE_MODE=zfs` registers the image directly into the local Falcon dataset
for testing. To produce a portable artifact for S3, build in raw/artifact mode:

```sh
cd ~/git/voxel
FALCON_DATASET=DATA/falcon \
  CAPTURE_MODE=raw \
  IMAGE_NAME=junos-23.2 \
  OUT="$PWD/voxel-image/out" \
  ./voxel-image/build-junos.sh 23.2R1.13
```

Upload the resulting `voxel-image/out/junos-23.2_0.raw.xz` to the Falcon assets
bucket.

After publishing a new image, local test machines may need the existing Falcon
base-image dataset destroyed/replaced so the new image is used.

## Running with diagnostics disabled

Failure diagnostics are enabled by default. Before collecting them, falcon-lab
attempts to start FRR and BIRD and unpause cEOS and cRPD so their normal CLI
and API paths are available. `--no-cleanup` preserves the topology after the
run, but does not prevent this diagnostic recovery.

To preserve the exact failure state for manual inspection, including peers
that the scenario left paused or stopped, disable diagnostics as well as
cleanup:

```sh
pfexec target/release/falcon-lab run interop bfd-static-routing \
  --no-cleanup --no-diag-on-fail
```

Use this combination when automated recovery would disturb the state being
investigated, such as when inspecting one node while its peer remains paused.
Without `--no-cleanup`, disabling diagnostics does not preserve the topology.
