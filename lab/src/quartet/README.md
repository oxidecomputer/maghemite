# Quartet

A testing topology with two rack routers (r0,r1) and two host routers (h0, h1).

When running this topology create a directory called `cargo-bay` and place the
`mg-illumos` and `riftadm` build artifacts in it, they'll get mouted at
`/opt/cargo-bay`.

## Setup Notes

### r0
```
./mg-illumos rack 100 1 1 fd00:1701:d::/64
```

### r1
```
./mg-illumos rack 101 1 1 fd00:1701:d::/64
```

### h0
```
./mg-illumos compute 102 0
```

### h1
```
./mg-illumos compute 103 0
```
