#!/usr/bin/env bash

set -euo pipefail

# === CONFIGURATION ===
ZGRAB2_BIN="${ZGRAB2_BIN:-/usr/local/bin/zgrab2}"
SCAN_PATH="${SCAN_PATH:-$(pwd)}"
PROBES_PATH="${PROBES_PATH:-$SCAN_PATH/probes}"
SENDERS="${SENDERS:-3000}"
TIMEOUT="${TIMEOUT:-15}"
SERVER_RATE_LIMIT="${SERVER_RATE_LIMIT:-}"
DNS_RATE_LIMIT="${DNS_RATE_LIMIT:-}"
CUSTOM_MODE=false

# === LOGGING ===
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'
log_info()    { echo -e "${GREEN}[INFO] $1${NC}"; }
log_error()   { echo -e "${RED}[ERROR] $1${NC}" >&2; }
log_warn()    { echo -e "${YELLOW}[WARN] $1${NC}"; }

# === USAGE ===
usage() {
    echo "Usage: $0 -P|--protocol PROTOCOL -f|--file INPUT_FILE [-c|--custom] [-o|--output OUTPUT_FILE] [-b|--blocklist BLOCKLIST_FILE]"
    echo "Supported protocols: s7comm modbus dnp3 iec104 gast"
    echo ""
    echo "Options:"
    echo "  -P, --protocol           Protocol to scan"
    echo "  -c, --custom             Use custom banner grabbing for native protocols (s7comm, modbus, dnp3)"
    echo "  -f, --file               Input file with IPs/targets"
    echo "  -o, --output             Output file (optional, defaults to results/zgrab2_PROTOCOL.jsonl)"
    echo "  -b, --blocklist          Blocklist file (optional, only used if explicitly provided)"
    echo "  -s, --senders            Number of concurrent senders (default: 3000)"
    echo "  -t, --timeout            Connection timeout in seconds (default: 15)"
    echo "  --server-rate-limit      Connections per second per target IP (optional, for ethical scanning)"
    echo "  --dns-rate-limit         DNS lookups per second (optional, for ethical scanning)"
    echo "  --ethical                Enable ethical scanning mode (senders=100, server-rate-limit=5, dns-rate-limit=1000, timeout=30)"
    echo "  -h, --help               Show this help"
    exit 1
}

# === ARGUMENT PARSING ===
PROTOCOL=""
INPUT_FILE=""
OUTPUT_FILE=""
BLOCKLIST=""
USER_PROVIDED_BLOCKLIST=false
ETHICAL_MODE=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        -P|--protocol)
            PROTOCOL="$2"
            shift 2
            ;;
        -f|--file)
            INPUT_FILE="$2"
            shift 2
            ;;
        -c|--custom)
            CUSTOM_MODE=true
            shift
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -b|--blocklist)
            BLOCKLIST="$2"
            USER_PROVIDED_BLOCKLIST=true
            shift 2
            ;;
        -s|--senders)
            SENDERS="$2"
            shift 2
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --server-rate-limit)
            SERVER_RATE_LIMIT="$2"
            shift 2
            ;;
        --dns-rate-limit)
            DNS_RATE_LIMIT="$2"
            shift 2
            ;;
        --ethical)
            ETHICAL_MODE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown argument: $1"
            usage
            ;;
    esac
done

if [[ -z "$PROTOCOL" || -z "$INPUT_FILE" ]]; then
    log_error "Protocol and input file are required."
    usage
fi

# === ETHICAL MODE CONFIGURATION ===
if [[ "$ETHICAL_MODE" == true ]]; then
    log_info "Ethical scanning mode enabled"
    SENDERS=400
    SERVER_RATE_LIMIT=10
    DNS_RATE_LIMIT=2000
    TIMEOUT=20
    log_info "Configured: senders=400, server-rate-limit=10/s/IP, dns-rate-limit=2000/s, timeout=20s"
    log_info "Expected scan rate: ~10-15 devices/second (~80-85% reduction in network noise vs default)"
fi

# === VALIDATE INPUT FILE ===
if [[ ! -f "$INPUT_FILE" ]]; then
    log_error "Input file not found: $INPUT_FILE"
    exit 1
fi

# === OUTPUT FILE DEFAULT ===
if [[ -z "$OUTPUT_FILE" ]]; then
    OUTPUT_FILE="$SCAN_PATH/results/zgrab2_${PROTOCOL}_$(date +%Y%m%d_%H%M%S).jsonl"
fi

LOG_FILE="$SCAN_PATH/logs/zgrab2_${PROTOCOL}_$(date +%Y%m%d_%H%M%S).log"
META_FILE="$SCAN_PATH/meta/zgrab2_${PROTOCOL}_$(date +%Y%m%d_%H%M%S).json"

# === BLOCKLIST HANDLING (ONLY IF USER PROVIDED) ===
if [[ "$USER_PROVIDED_BLOCKLIST" == true ]]; then
    if [[ ! -f "$BLOCKLIST" ]]; then
        log_error "Specified blocklist not found: $BLOCKLIST"
        exit 1
    fi
    log_info "Using provided blocklist: $BLOCKLIST"
else
    BLOCKLIST=""
    log_info "No blocklist provided by user"
fi

# === ENSURE DIRECTORIES EXIST ===
mkdir -p "$(dirname "$OUTPUT_FILE")" "$(dirname "$LOG_FILE")"

# === PROTOCOL CONFIGURATION ===
get_protocol_config() {
    case "$PROTOCOL" in
                s7comm)
            if [[ "$CUSTOM_MODE" == true ]]; then
                MODULE="banner"
            else
                MODULE="siemens"
            fi
            PORT="102"
            ;;
        modbus)
            if [[ "$CUSTOM_MODE" == true ]]; then
                MODULE="banner"
            else
                MODULE="modbus"
            fi
            PORT="502"
            ;;
        dnp3)
            if [[ "$CUSTOM_MODE" == true ]]; then
                MODULE="banner"
            else
                MODULE="dnp3"
            fi
            PORT="20000"
            ;;
        iec104)
            MODULE="banner"
            PORT="2404"
            ;;
        gast)
            MODULE="banner"
            PORT="10001"
            ;;
        *)
            log_error "Unsupported protocol: $PROTOCOL"
            exit 2
            ;;
    esac
}

# === PAYLOAD SELECTION ===
prepare_payload() {
	case "$PROTOCOL" in
	    s7comm)
		PAYLOAD="$PROBES_PATH/s7comm.bin"
		;;
	    modbus)
		PAYLOAD="$PROBES_PATH/modbus.bin"
		;;
	    dnp3)
		PAYLOAD="$PROBES_PATH/dnp3.bin"
		;;
	    iec104)
		PAYLOAD="$PROBES_PATH/iec104.bin"
		;;
	    gast)
		PAYLOAD="$PROBES_PATH/gast.bin"
		;;
	    *)
		PAYLOAD=""
		;;
	esac

	# Validate payload file exists for protocols that need it
	if [[ -n "$PAYLOAD" && ! -f "$PAYLOAD" ]]; then
	    log_error "Payload file not found: $PAYLOAD"
	    log_error "Please ensure the probe file exists in $PROBES_PATH/"
	    exit 1
	fi
}

# === ZGRAB2 RUNNER ===
run_zgrab2() {
    get_protocol_config
    prepare_payload

    # Build base command with explicit port
    CMD=("$ZGRAB2_BIN" "$MODULE" \
        --input-file "$INPUT_FILE" \
        --output-file "$OUTPUT_FILE" \
        --metadata-file "$META_FILE" \
        --log-file "$LOG_FILE"
        --port "$PORT")

    # Add blocklist ONLY if user explicitly provided it
    if [[ -n "$BLOCKLIST" ]]; then
        CMD+=(--blocklist-file "$BLOCKLIST")
    fi

    # Add rate limiting flags if specified
    if [[ -n "$SERVER_RATE_LIMIT" ]]; then
        CMD+=(--server-rate-limit "$SERVER_RATE_LIMIT")
    fi

    if [[ -n "$DNS_RATE_LIMIT" ]]; then
        CMD+=(--dns-rate-limit "$DNS_RATE_LIMIT")
    fi

    # Add protocol-specific options with corrected timeout handling
    case "$MODULE" in
        banner)
            CMD+=(--probe-file "$PAYLOAD" --connect-timeout "${TIMEOUT}")
            ;;
        siemens|dnp3|modbus)
            if [[ "$CUSTOM_MODE" == true ]]; then
                CMD+=(--probe-file "$PAYLOAD" --connect-timeout "${TIMEOUT}" --verbose)
            else
                CMD+=(--connect-timeout "${TIMEOUT}s" --verbose)
            fi
            ;;
    esac

    # Add concurrency for non-banner modules
    case "$MODULE" in
        banner)
            # Banner module doesn't support --gomaxprocs
            ;;
        *)
            CMD+=(--gomaxprocs "$SENDERS")
            ;;
    esac

    log_info "Starting zgrab2 scan for protocol: $PROTOCOL"
    log_info "Target port: $PORT"
    log_info "Input file: $INPUT_FILE ($(wc -l < "$INPUT_FILE") targets)"
    log_info "Output file: $OUTPUT_FILE"
    log_info "Log file: $LOG_FILE"
    log_info "Metadata file: $META_FILE"

    if [[ "$MODULE" == "banner" || "$CUSTOM_MODE" == true ]]; then
        log_info "Using payload file: $PAYLOAD ($(wc -c < "$PAYLOAD") bytes)"
    else
        log_info "Using default zgrab2 module probe"
    fi

    if [[ -n "$BLOCKLIST" ]]; then
        log_info "Blocklist: $BLOCKLIST"
    else
        log_info "Blocklist: None"
    fi

    log_info "Timeout: ${TIMEOUT}s"
    log_info "Senders (concurrency): $SENDERS"

    if [[ -n "$SERVER_RATE_LIMIT" ]]; then
        log_info "Server rate limit: ${SERVER_RATE_LIMIT} connections/second/IP"
    else
        log_info "Server rate limit: 20 connections/second/IP (zgrab2 default)"
    fi

    if [[ -n "$DNS_RATE_LIMIT" ]]; then
        log_info "DNS rate limit: ${DNS_RATE_LIMIT} lookups/second"
    else
        log_info "DNS rate limit: 10000 lookups/second (zgrab2 default)"
    fi
    
    log_info "Running: ${CMD[*]}"
    "${CMD[@]}" 2>&1 | tee "$LOG_FILE" || {
        log_error "zgrab2 command failed"
        exit 1
    }
    
    local result_count
    result_count="$(wc -l < "$OUTPUT_FILE" 2>/dev/null || echo "0")"
    log_info "Scan complete. Results: $result_count entries in $OUTPUT_FILE"
}

# === MAIN ===
run_zgrab2
