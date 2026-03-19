# cwe_map.sh — supported CWEs and their metadata.
# Compatible with bash 3.2+ (macOS default).
#
# To add a new CWE:
#   1. Add a "slug:label" entry to CWE_MAP below
#   2. Run CWE=CWE-XX ./scripts/generate_cve_prs.sh    (in decomposition repo)
#   3. Run CWE=CWE-XX ./scripts/publish_cwe_benchmark.sh (in decomposition repo)

# Each entry: "slug:Human label"
CWE_MAP=(
    "cwe89:CWE-89: SQL Injection"
    "cwe79:CWE-79: Cross-Site Scripting (XSS)"
    "cwe22:CWE-22: Path Traversal"
)

# Derived: plain list of slugs
CWE_SLUGS=()
for _entry in "${CWE_MAP[@]}"; do
    CWE_SLUGS+=("${_entry%%:*}")
done
unset _entry

# cwe_label <slug> — print the human label for a slug, or empty string if unknown
cwe_label() {
    local slug="$1"
    for _entry in "${CWE_MAP[@]}"; do
        if [[ "${_entry%%:*}" == "$slug" ]]; then
            echo "${_entry#*:}"
            return 0
        fi
    done
    return 1
}

# cwe_is_supported <slug> — returns 0 if supported, 1 otherwise
cwe_is_supported() {
    cwe_label "$1" > /dev/null 2>&1
}
