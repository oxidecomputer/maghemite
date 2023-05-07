## Tests

This directory contains a suite of tests. These tests work by

- Launching a topology of zones.
- Running maghemite routers in those zones.
- Performing a bunch of actions on those routers.
- Cause chaos in zones and links between zones while routers are running.
- Ensure that expectations are met in spite of chaos.

The test suite can be run locally in the same way as it is run in CI.

```
.github/buildomat/jobs/test
```

Standard cargo testing mechanisms also work fine.
