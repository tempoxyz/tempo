terraform {
    required_providers {
        latitudesh = {
            source = "latitudesh/latitudesh"
            version = "2.3.0"
        }
    }
}

resource "latitudesh_server" "server" {
    for_each = var.nodes

    billing = "hourly"
    # hostname = "tempo--${var.chain_name}--${each.key}"
    hostname = "${each.key}"
    operating_system = "ubuntu_24_04_x64_lts"
    plan = each.value.size
    site = each.value.region
    project = var.project_id
    ssh_keys = var.ssh_key_ids
    raid = "raid-0"
}

output "node_addresses" {
    value = [for name, server in latitudesh_server.server : server.primary_ipv4]
}