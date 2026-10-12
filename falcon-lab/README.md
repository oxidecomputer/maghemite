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
spine-leaf  bare
spine-leaf  bgp-numbered
spine-leaf  bgp-unnumbered
```

`mgd-duo` connects two Maghemite nodes. `interop` connects a Maghemite DUT to
FRR, Arista EOS, Juniper cRPD, BIRD 2, and a second Maghemite node.
`interop-3-link` uses the same peers with three links per peer.

- `bgp-unnumbered` checks dual-stack route exchange and interop ECMP.
- `bgp-md5` checks authenticated numbered and unnumbered sessions, stability,
  and multipath route exchange.
- `bfd-static-routing` checks dual-stack BFD and static-route failover/recovery.

Run and cleanup commands both take a topology and scenario:

```sh
pfexec target/release/falcon-lab run interop bgp-unnumbered --no-cleanup
pfexec target/release/falcon-lab cleanup interop bgp-unnumbered
```

The `bare` scenarios launch their topology without applying protocol
configuration.

## Spine-leaf BGP transit

`spine-leaf` connects two mgd leaves (`ox1`, `ox2`) to four spines (`frr`,
`eos`, `junos`, `bird`), one per third-party interop stack. Each leaf has one
link to every spine; there are no leaf-to-leaf or spine-to-spine links.
In the BGP scenarios, both leaves run SoftNPU/Dendrite to check dataplane
installation as well as BGP receipt. The spines transit BGP routes and
originate no test prefixes.

| Node | ASN | Originated IPv4 prefix | Originated IPv6 prefix |
| --- | --- | --- | --- |
| ox1 | 65001 | 198.51.100.0/24 | 2001:db8:1::/64 |
| ox2 | 65002 | 203.0.113.0/24 | 2001:db8:2::/64 |
| frr | 65101 | — | — |
| eos | 65102 | — | — |
| junos | 65103 | — | — |
| bird | 65104 | — | — |

On each leaf, `qsfp0` through `qsfp3` connect to FRR, EOS, Junos, and BIRD,
respectively. The first and second data interfaces on each spine connect to
`ox1` and `ox2`.

- `bare` launches only the VM graph, without installing the leaf NPU software
  or applying BGP configuration. It clears stale staged Junos configuration
  before boot, as the other interop bare scenarios do.
- `bgp-numbered` assigns IPv4 and IPv6 addresses to every data link. Each
  link has two eBGP sessions: IPv4 transport for IPv4 unicast, and IPv6
  transport for IPv6 unicast. Links use `10.20.N.0/24` and `fd20:H::/64`,
  where N is 0–3 for ox1 and 4–7 for ox2, and H is N + 1. The leaf uses
  host 1 and the spine host 2.
- `bgp-unnumbered` leaves data links IPv6 link-local only, with automatically
  generated addresses. One link-local eBGP session per link carries both
  families, using extended next hops for IPv4. BIRD receives the discovered
  leaf link-local addresses explicitly; router advertisements drive mgd's
  peer discovery. Management links remain separately numbered in both scenarios.

Each BGP scenario checks all sessions are Established, then checks that each
leaf receives and selects four paths for the other leaf's two prefixes and
installs them on all four spine-facing Dendrite ports. No custom path
attribute is injected or asserted yet.

Run one scenario at a time from the directory containing the staged
`cargo-bay/` (including the Juniper license described below):

```sh
pfexec target/release/falcon-lab run spine-leaf bare --no-cleanup
pfexec target/release/falcon-lab cleanup spine-leaf bare
pfexec target/release/falcon-lab run spine-leaf bgp-numbered --no-cleanup
pfexec target/release/falcon-lab cleanup spine-leaf bgp-numbered
pfexec target/release/falcon-lab run spine-leaf bgp-unnumbered --no-cleanup
pfexec target/release/falcon-lab cleanup spine-leaf bgp-unnumbered
```

## Runtime cargo-bay contents

Before running any topology, `cargo-bay/` must contain:

- `mgd` and `ddmd`, staged by local test setup or the Buildomat job.

The interop and spine-leaf topologies additionally require:

- `falcon-juniper-license.key`, a Juniper license file. This file is a secret:
  do not commit it, print it, include it in diagnostics, or pass its contents in
  command-line arguments.

`falcon-lab` writes non-secret Junos topology config as
`cargo-bay/<node>-junos.set`. The staged file is a complete non-interactive
Junos CLI input file: it starts with `configure`, contains `set ...` commands,
and ends with `commit`.

Junos topology config is per-run state. `falcon-lab` removes stale
`cargo-bay/*-junos.set` files before launching or cleaning up an interop or
spine-leaf topology so the guest-side apply service cannot consume
configuration left by an earlier topology. Do not put persistent hand-written
Junos config in files matching that pattern.

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
[`oxidecomputer/voxel`](https://github.com/oxidecomputer/voxel) repository.

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
