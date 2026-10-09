# Falcon lab

`falcon-lab` runs Maghemite integration topologies under Falcon. A topology
defines the VM graph, while a scenario configures and tests that topology. The
topologies use prebuilt Falcon base images for Helios, Debian/FRR, cEOS, and
Junos/cRPD nodes, plus a per-run `cargo-bay/` 9p share for binaries and runtime
configuration.

## Topologies and scenarios

Supported topology/scenario pairs are:

```text
mgd-duo  bare
mgd-duo  bgp-unnumbered
interop  bare
interop  bgp-unnumbered
interop  bfd-static-routing
bgp-add-path bare
bgp-add-path frr
bgp-add-path arista
bgp-add-path juniper
```

`mgd-duo` connects two Maghemite nodes. `interop` connects a Maghemite DUT to
FRR, Arista EOS, Juniper cRPD, and a second Maghemite node.

Run and cleanup commands both take a topology and scenario:

```sh
pfexec target/release/falcon-lab run interop bgp-unnumbered --no-cleanup
pfexec target/release/falcon-lab cleanup interop bgp-unnumbered
```

The `bare` scenarios launch their topology without applying protocol
configuration.

## ADD-PATH lab

`bgp-add-path` uses direct VM links (no SoftNPU) to exercise multiple paths
received from one router over a single BGP session per address family:

```text
ox (mgd, AS65000) --- transit (AS65001) --- frr1 (AS65002)
                            |
                            +------------ frr2 (AS65003)
```

The scenario name identifies the middle speaker (`transit`). The two origin
nodes, `frr1` and `frr2`, remain FRR regardless of the middle speaker's vendor.
There is no mgd transit variant. `bare` launches the FRR graph without protocol
configuration.

| Scenario | Transit image | ADD-PATH transmit configuration toward ox | Deployment |
| --- | --- | --- | --- |
| `frr` | `debian-13.2` | `addpath-tx-all-paths` | `bgpaddpath_frr` |
| `arista` | `eos-4.35` | `additional-paths send any` | `bgpaddpath_eos` |
| `juniper` | `junos-23.2` | `add-path send path-count 2` | `bgpaddpath_jun` |

All three configured scenarios use separate numbered IPv4 and IPv6 eBGP
sessions on all three links. Each session carries only its matching unicast
address family, so IPv4 routes use IPv4 nexthops and IPv6 routes use IPv6
nexthops. `frr1` and `frr2` each originate `203.0.113.0/24` and
`2001:db8:100::/64`, backed by discard routes. The transit speaker enables
ADD-PATH transmit toward `ox` for both families. Each scenario first checks
that the transit speaker learns two paths per prefix, then checks that `mgd`
imports two paths per prefix from it. This does not assert ECMP or forwarding:
both received paths use the transit speaker.

On an illumos/Falcon host, stage the Helios `mgd` binary in `cargo-bay/mgd`,
then run:

```sh
cargo build --release -p falcon-lab
scenario=arista # frr, arista, or juniper
pfexec target/release/falcon-lab run bgp-add-path "$scenario" --no-cleanup
```

Run one scenario at a time and clean it up before launching the next, since
the node console files and cargo-bay are shared. The Juniper scenario requires
`cargo-bay/falcon-juniper-license.key` and the guest services described below.

These scenarios deliberately require working ADD-PATH reception for **both**
families. They will fail if `mgd` does not negotiate IPv6 ADD-PATH, cannot decode
the updates, or does not retain both paths. `--no-cleanup` preserves the lab
even after failure so you can inspect or change the running configuration.
Use `bare` for an unconfigured FRR lab. No `ddmd` or Dendrite is needed.
Only `arista` and `juniper` require their respective vendor images; only
`juniper` needs the Juniper license. The Debian nodes need DHCP and
package-repository access to install FRR.

The data interfaces are:

| Link | Fixed endpoint | FRR transit | Arista transit | Juniper transit |
| --- | --- | --- | --- | --- |
| ox–transit | ox `vioif0` | `enp0s6` | `Ethernet1` | `eth1` |
| transit–frr1 | frr1 `enp0s6` | `enp0s7` | `Ethernet2` | `eth2` |
| transit–frr2 | frr2 `enp0s6` | `enp0s8` | `Ethernet3` | `eth3` |

| Link | Transit addresses | Other endpoint addresses |
| --- | --- | --- |
| ox–transit | `10.0.0.1/30`, `fd00:0::1/64` | ox: `10.0.0.2/30`, `fd00:0::2/64` |
| transit–frr1 | `10.0.1.1/30`, `fd00:1::1/64` | frr1: `10.0.1.2/30`, `fd00:1::2/64` |
| transit–frr2 | `10.0.2.1/30`, `fd00:2::1/64` | frr2: `10.0.2.2/30`, `fd00:2::2/64` |

Management uses ox `vioif1`, transit host `enp0s9`, and frr1/frr2 `enp0s7`.
The cEOS/cRPD images must discover this management NIC and attach all three
preceding data NICs to their containers in link order, using the names above.
They must not assume the single-data-link or SoftNPU PCI layout of `interop`.
These multi-port image assumptions require validation on a Falcon host.

Open the transit node's host console with:

```sh
pfexec target/release/falcon-lab serial transit
```

For the FRR scenario, inspect capability negotiation and paths with:

```sh
vtysh -c 'show bgp neighbors'
vtysh -c 'show bgp ipv4 unicast 203.0.113.0/24'
vtysh -c 'show bgp ipv6 unicast 2001:db8:100::/64'
```

For Arista use `docker exec ceos Cli -c 'show ip bgp neighbors'` and
`show ip bgp` / `show ipv6 bgp` in the same CLI. For Juniper use
`docker exec crpd1 cli -c 'show bgp neighbor'` and `show route table inet.0`
/ `show route table inet6.0`. Failure diagnostics include vendor BGP state;
Junos configuration diagnostics redact the license.

For manual withdrawal testing, remove a `network` statement in the relevant
address family on `frr1` or `frr2`. `mgd` should retain the other path; adding
the statement back should restore two paths. The automated scenario checks
initial receipt only, not path IDs or withdrawal behavior.

Clean up using the same scenario name that you launched:

```sh
pfexec target/release/falcon-lab cleanup bgp-add-path "$scenario"
```

## Runtime cargo-bay contents

For the interop scenarios, `cargo-bay/` must contain:

- `mgd` and `ddmd`, staged by local test setup or the Buildomat job.

The `mgd-duo` and `bgp-add-path` BGP scenarios only need `mgd`. Bare scenarios
still need the `cargo-bay/` directory for their mounts, but no binaries.

The interop topology and `bgp-add-path juniper` additionally require:

- `falcon-juniper-license.key`, a Juniper license file. This file is a secret:
  do not commit it, print it, include it in diagnostics, or pass its contents in
  command-line arguments.

`falcon-lab` writes non-secret Junos topology config as
`cargo-bay/<node>-junos.set`. The staged file is a complete non-interactive
Junos CLI input file: it starts with `configure`, contains `set ...` commands,
and ends with `commit`.

Junos topology config is per-run state. `falcon-lab` removes stale
`cargo-bay/*-junos.set` files before launching or cleaning up an interop
topology or `bgp-add-path juniper`, so the guest-side apply service cannot
consume configuration left by an earlier topology. Do not put persistent
hand-written Junos config in files matching that pattern.

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

Failure diagnostics are enabled by default. For faster local iteration while
preserving the failed topology, use:

```sh
pfexec target/release/falcon-lab run interop bfd-static-routing \
  --no-cleanup --no-diag-on-fail
```

Even with `--no-diag-on-fail`, interop scenarios make a best-effort attempt to
restart FRR and unpause cEOS/cRPD before returning the failure.
