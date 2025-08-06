generate "providers" {
    path = "provider.tf"
    if_exists = "overwrite_terragrunt"
    contents = <<EOF
provider "latitudesh" {
    auth_token = "${get_env("LATITUDESH_API_KEY")}"
}
EOF
}