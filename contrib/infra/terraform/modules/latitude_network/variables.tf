variable "nodes" {
    description = "A list of nodes to deploy"
    type = map(object({
        region = string
        size = string
    }))
}

variable "environment" {
    description = "The environment to deploy to"
}

variable "chain_name" {
    description = "The name of the chain"
}

variable "project_id" {
    description = "The ID of the project to deploy to"
}

variable "ssh_key_ids" {
    description = "The IDs of the SSH keys to use for the nodes"
    type = list(string)
}