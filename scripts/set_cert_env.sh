#!/bin/bash

convert_and_export(){
    local pem_file=$1
    local env_name=$2

    if [[ -f "$pem_file" ]]; then
        # read file and convert to base64
        local encoded=$(base64 -w 0 "$pem_file")
        
        # export to env var
        export $env_name=$encoded
        echo "Exported $env_name"

    else
        echo "$pem_file file not found."
    fi 

}

# ex
convert_and_export "server-cert.pem" "CARAPACE_SERVER_CERT"
convert_and_export "server-key.pem" "CARAPACE_SERVER_KEY"
convert_and_export "client-cert.pem" "CARAPACE_CLIENT_CERT"
convert_and_export "client-key.pem" "CARAPACE_CLIENT_KEY"
convert_and_export "db-client-cert.pem" "CARAPACE_DB_CLIENT_CERT"
convert_and_export "db-client-key.pem" "CARAPACE_DB_CLIENT_KEY"

