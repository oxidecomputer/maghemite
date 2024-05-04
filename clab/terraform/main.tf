terraform {
  required_providers {
    maghemite = {
      source = "registry.terraform.io/oxidecomputer/maghemite"
    }
  }
}

provider "maghemite" {}

resource "maghemite_bgp_router" "oxpop" {
  asn = 65547
  graceful_shutdown = false
  id = 1701
  listen = "0.0.0.0:0"
}

resource "maghemite_bgp_origin4" "oxpop" {
  asn = 65547
  prefixes = ["198.51.100.0/24", "192.168.12.0/24"]

  depends_on = [maghemite_bgp_router.oxpop]
}

resource "maghemite_bgp_checker" "oxpop" {
  asn = 65547
  code = file("checker.rhai") 

  depends_on = [maghemite_bgp_router.oxpop]
}

resource "maghemite_bgp_shaper" "oxpop" {
  asn = 65547
  code = file("shaper.rhai") 

  depends_on = [maghemite_bgp_router.oxpop]
}

resource "maghemite_bgp_neighbor" "transit" {
  asn = 65547
  name = "transit"
  host = "169.254.10.1:179"
  hold_time = 15
  keepalive = 5
  idle_hold_time = 6
  delay_open = 0
  connect_retry = 5
  resolution = 100
  group = "qsfp0"
  passive = false
  remote_asn = 64500
  min_ttl = 255
  md5_auth_key = "hypermuffin"
  multi_exit_discriminator = 47 
  communities = []
  enforce_first_as = false

  depends_on = [maghemite_bgp_router.oxpop]
}

resource "maghemite_bgp_neighbor" "cdn" {
  asn = 65547
  name = "cdn"
  host = "169.254.20.1:179"
  hold_time = 15
  keepalive = 5
  idle_hold_time = 6
  delay_open = 0
  connect_retry = 5
  resolution = 100
  group = "qsfp1"
  passive = false
  remote_asn = 64501
  min_ttl = 255
  md5_auth_key = "hypermuffin"
  multi_exit_discriminator = 47 
  communities = []
  enforce_first_as = false

  depends_on = [maghemite_bgp_router.oxpop]
}

resource "maghemite_bgp_neighbor" "pcwest" {
  asn = 65547
  name = "pcwest"
  host = "169.254.30.1:179"
  hold_time = 15
  keepalive = 5
  idle_hold_time = 6
  delay_open = 0
  connect_retry = 5
  resolution = 100
  group = "qsfp2"
  passive = false
  remote_asn = 64502
  min_ttl = 255
  md5_auth_key = "hypermuffin"
  multi_exit_discriminator = 47 
  communities = []
  enforce_first_as = false

  depends_on = [maghemite_bgp_router.oxpop]
}

resource "maghemite_bgp_neighbor" "pceast" {
  asn = 65547
  name = "pceast"
  host = "169.254.40.1:179"
  hold_time = 15
  keepalive = 5
  idle_hold_time = 6
  delay_open = 0
  connect_retry = 5
  resolution = 100
  group = "qsfp3"
  passive = false
  remote_asn = 64502
  min_ttl = 255
  md5_auth_key = "hypermuffin"
  multi_exit_discriminator = 47 
  communities = []
  enforce_first_as = false

  depends_on = [maghemite_bgp_router.oxpop]
}

output "oxpop_bgp_router" {
  value = maghemite_bgp_router.oxpop
}

output "oxpop_bgp_origin4" {
  value = maghemite_bgp_origin4.oxpop
}

output "transit_bgp_neighbor" {
  sensitive = true
  value = maghemite_bgp_neighbor.transit
}

output "cdn_bgp_neighbor" {
  sensitive = true
  value = maghemite_bgp_neighbor.cdn
}

output "pcwest_bgp_neighbor" {
  sensitive = true
  value = maghemite_bgp_neighbor.pcwest
}

output "pceast_bgp_neighbor" {
  sensitive = true
  value = maghemite_bgp_neighbor.pceast
}

/* XXX
data "maghemite_bgp_neighbors" "oxpop" {
  asn = 65547
}
output "example_bgp_neighbors" {
  value = data.maghemite_bgp_neighbors.oxpop
}
*/
