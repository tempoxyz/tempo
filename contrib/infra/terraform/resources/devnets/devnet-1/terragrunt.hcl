include "root" {
    path = find_in_parent_folders("root.hcl")
}

terraform {
    source = find_in_parent_folders("modules/latitude_network")
}

inputs = {
    environment = "dev"
    chain_name = "devnet-1"
    nodes = {
        "node-1" = {
            size = "f4-metal-medium"
            region = "LON2"
        }
        "node-2" = {
            size = "f4-metal-medium"
            region = "LON2"
        }
        "node-3" = {
            size = "f4-metal-medium"
            region = "LON2"
        }
    }
    project_id = "proj_jv6m5JyBVNLPe"
    ssh_key_ids = [
        "ssh_ZWr75Z8vm0A91"
    ]
}