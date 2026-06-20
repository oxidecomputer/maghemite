# Falcon lab

`falcon-lab` runs Maghemite integration topologies under Falcon. The
topologies use prebuilt Falcon base images for Helios, Debian/FRR, cEOS, and
Junos/cRPD nodes, plus a per-run `cargo-bay/` 9p share for binaries and runtime
configuration.

## Runtime cargo-bay contents

Before running Junos topologies, `cargo-bay/` must contain:

- `mgd` and `ddmd`, staged by local test setup or the Buildomat job.
- `falcon-juniper-license.key`, a Juniper license file. This file is a secret:
  do not commit it, print it, include it in diagnostics, or pass its contents in
  command-line arguments.

`falcon-lab` writes non-secret Junos topology config as
`cargo-bay/<node>-junos.set`. The staged file is a complete non-interactive
Junos CLI input file: it starts with `configure`, contains `set ...` commands,
and ends with `commit`.

Junos topology config is per-run state. `falcon-lab` removes stale
`cargo-bay/*-junos.set` files before launching a quartet topology so the
guest-side apply service cannot consume configuration left behind by an earlier
topology. Do not put persistent hand-written Junos config in files matching
that pattern.

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
pfexec ./falcon-lab run --no-cleanup --no-diag-on-fail quartet-bfd-static-routing
```

Even with `--no-diag-on-fail`, quartet tests make a best-effort attempt to resume
FRR's `bfdd` and unpause cEOS/cRPD before returning the failure.
