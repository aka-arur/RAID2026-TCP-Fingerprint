#!/usr/bin/env bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
ORANGE='\033[38;5;208m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO] $1${NC}"
}

log_fatal() {
    echo -e "${RED}[FATAL] $1${NC}" >&2
}

log_output() {
    echo -e "${YELLOW}[LOG] $1${NC}"
}

log_warnning() {
    echo -e "${ORANGE}[WARNING] $1${NC}"
}

SCAN_PATH="${SCAN_PATH:-/data/scans}"

usage() {
    echo "Usage: $0 -P|--protocol PROTOCOL"
    echo "Options:"
    echo "  -P, --protocol PROTOCOL       Set the protocol to scan (http, modbus, ftp, s7comm, iec104, gast, dnp3, all)"
    echo "  -h, --help                    Display this help message"
    echo ""
    echo "Note: DNP3 protocol will be scanned over both TCP and UDP on port 20000"
    exit 1
}

# Parse arguments
PROTOCOL=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -P|--protocol)
            PROTOCOL="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_fatal "Unknown option: $1"
            usage
            ;;
    esac
done

if [ -z "$PROTOCOL" ]; then
    log_fatal "Error: Protocol must be specified using -P or --protocol"
    usage
fi

# Supported protocols
SUPPORTED_PROTOCOLS="modbus s7comm iec104 gast dnp3 all"

if ! echo "$SUPPORTED_PROTOCOLS" | grep -qw "$PROTOCOL"; then
    log_fatal "Error: Unsupported protocol '$PROTOCOL'"
    log_info "Supported protocols: $SUPPORTED_PROTOCOLS"
    exit 1
fi

run_zmap() {
    local conf="$1"
    local protocol_variant="$2"  # Optional parameter for protocol variants (tcp/udp)
    
    # Determine config file name and output file suffix
    local config_suffix="$conf"
    local output_suffix="$conf"
    
    if [[ -n "$protocol_variant" ]]; then
        config_suffix="${conf}_${protocol_variant}"
        output_suffix="${conf}_${protocol_variant}"
    fi
    
    local config_file="$SCAN_PATH/protocol_conf/zmap_${config_suffix}.conf"
    local blocklist_file="$SCAN_PATH/blocklist.conf"
    local meta_file="$SCAN_PATH/meta/zmap_${output_suffix}_summary_$(date +"%Y%m%d_%H%M%S").json"
    local log_dir="$SCAN_PATH/logs"
    local output_file="$SCAN_PATH/results/zmap_${output_suffix}_$(date +"%Y%m%d_%H%M%S").jsonl"
    local interface="${INTERFACE:-eth0}"

    if [[ ! -f "$config_file" ]]; then
        log_fatal "Config file not found: $config_file"
        exit 2
    fi

    if [[ -n "$protocol_variant" ]]; then
        log_info "Running zmap scan for protocol: $conf ($protocol_variant)"
    else
        log_info "Running zmap scan for protocol: $conf"
    fi
    
    /usr/local/sbin/zmap --config="$config_file" \
        --blocklist-file="$blocklist_file" \
        --metadata-file="$meta_file" \
        --log-directory="$log_dir" \
        --output-file="$output_file" \
        --interface="$interface"

    if [ $? -ne 0 ]; then
        log_fatal "zmap command failed for $conf${protocol_variant:+ ($protocol_variant)}"
        exit 1
    fi

    log_output "Output saved to $output_file"
}

# Special handling for DNP3 protocol
if [[ "$PROTOCOL" == "dnp3" ]]; then
    log_info "DNP3 protocol detected - scanning both TCP and UDP variants on port 20000"
    
    # Run UDP scan
    run_zmap "$PROTOCOL" "udp"
    # Run TCP scan
    run_zmap "$PROTOCOL" "tcp"

elif [[ "$PROTOCOL" == "all" ]]; then
    log_info "All protocols selected - scanning all ports simultaneously"
    
    # Run scan with all protocols config file
    run_zmap "$PROTOCOL"

    
    if [ $? -ne 0 ]; then
        log_fatal "zmap command failed for $conf${protocol_variant:+ ($protocol_variant)}"
        exit 1
    fi


else
    # Standard single protocol scan
    run_zmap "$PROTOCOL"
fi

