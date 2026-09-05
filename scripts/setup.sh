#!/usr/bin/env bash
# One-shot local lab bring-up for ebpf-fast-relays (generic Linux host).
# Not Hostinger-specific. Prefer: sudo ./scripts/setup.sh
#
# Expected sibling layout (next to this repo):
#   ../quic-go-prio-packs          <- danielpfeifer02/quic-go-prio-packs
#   ../gst-prio-moq-app            <- danielpfeifer02/gst-prio-moq-app
#   ../gst-prio-moq-app/priority-moqtransport  <- danielpfeifer02/priority-moqtransport
#   ../crypto                      <- danielpfeifer02/ebpf-go-crypto
#   ../plain-quic-go-lib/quic-go   <- danielpfeifer02/quic-go-no-crypto

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PARENT_DIR="$(cd "${REPO_ROOT}/.." && pwd)"
SHELL_DIR="${REPO_ROOT}/src/shell"
BPF_DIR="${REPO_ROOT}/src/bpf"
CHAT_DIR="${REPO_ROOT}/src/go/examples/priority_drop_chat"
VIDEO_DIR="${REPO_ROOT}/src/go/examples/priority_drop_video"

log()  { printf '\n==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

need_cmd() {
	command -v "$1" >/dev/null 2>&1
}

# ---------- Phase 1: privileges + kernel features ----------
phase_checks() {
	log "Phase 1: privileges and kernel features"

	if [[ "${EUID}" -ne 0 ]]; then
		die "This script needs root for namespaces/bridges/tc. Re-run as: sudo $0"
	fi

	if [[ ! -e /sys/kernel/btf/vmlinux ]]; then
		die "Kernel BTF not found at /sys/kernel/btf/vmlinux. Enable CONFIG_DEBUG_INFO_BTF / install a BTF-enabled kernel."
	fi
	echo "BTF: OK (/sys/kernel/btf/vmlinux)"

	if ! need_cmd tc; then
		die "'tc' (iproute2) not found; install iproute2 (Phase 2) or ensure it is on PATH."
	fi

	# clsact smoke test on lo (add if missing, then remove our qdisc)
	local smoke_added=0
	if ! tc qdisc show dev lo 2>/dev/null | grep -q clsact; then
		if ! tc qdisc add dev lo clsact 2>/tmp/ebpf_setup_clsact.err; then
			die "clsact qdisc not supported on this kernel (tc qdisc add dev lo clsact failed): $(cat /tmp/ebpf_setup_clsact.err 2>/dev/null || true)"
		fi
		smoke_added=1
	fi
	echo "clsact on lo: OK"
	if [[ "${smoke_added}" -eq 1 ]]; then
		tc qdisc del dev lo clsact 2>/dev/null || true
	fi
}

# ---------- Phase 2: apt dependencies ----------
APT_PACKAGES=(
	build-essential
	clang
	llvm
	golang-go
	bridge-utils
	libelf-dev
	libbpf-dev
	iproute2
	iptables
	iputils-ping
	pkg-config
	git
	ca-certificates
)

# Optional gstreamer (video example)
GST_PACKAGES=(
	libgstreamer1.0-dev
	libgstreamer-plugins-base1.0-dev
	gstreamer1.0-plugins-base
	gstreamer1.0-plugins-good
	gstreamer1.0-tools
)

pkg_installed() {
	dpkg -s "$1" >/dev/null 2>&1
}

phase_apt() {
	log "Phase 2: apt dependencies"

	if ! need_cmd apt-get; then
		warn "apt-get not found; skipping package install. Ensure clang, llvm, golang, bridge-utils, libelf-dev, libbpf-dev, iproute2, etc. are present."
		return 0
	fi

	export DEBIAN_FRONTEND=noninteractive
	apt-get update -y

	local missing=()
	local p
	for p in "${APT_PACKAGES[@]}"; do
		if pkg_installed "$p"; then
			echo "already installed: $p"
		else
			missing+=("$p")
		fi
	done

	# bpftool / linux-tools (distro-dependent)
	if ! need_cmd bpftool; then
		if apt-cache show bpftool >/dev/null 2>&1; then
			missing+=("bpftool")
		else
			local kver
			kver="$(uname -r)"
			if apt-cache show "linux-tools-${kver}" >/dev/null 2>&1; then
				missing+=("linux-tools-${kver}")
			elif apt-cache show linux-tools-generic >/dev/null 2>&1; then
				missing+=("linux-tools-generic")
			else
				warn "bpftool package not found in apt; install bpftool manually if needed."
			fi
		fi
	else
		echo "already present: bpftool"
	fi

	# Prefer clang-14 if the distro still ships it (older BPF backend)
	if ! need_cmd clang-14 && apt-cache show clang-14 >/dev/null 2>&1; then
		missing+=("clang-14")
	fi

	if [[ "${#missing[@]}" -gt 0 ]]; then
		echo "Installing: ${missing[*]}"
		apt-get install -y "${missing[@]}"
	else
		echo "All required apt packages already present."
	fi

	if [[ "${SKIP_GST:-0}" != "1" ]]; then
		local gst_missing=()
		for p in "${GST_PACKAGES[@]}"; do
			if ! pkg_installed "$p"; then
				if apt-cache show "$p" >/dev/null 2>&1; then
					gst_missing+=("$p")
				fi
			fi
		done
		if [[ "${#gst_missing[@]}" -gt 0 ]]; then
			echo "Installing optional gstreamer packages for video example: ${gst_missing[*]}"
			apt-get install -y "${gst_missing[@]}" || warn "gstreamer install failed; video example may not build (chat still OK)."
		else
			echo "gstreamer packages already present (or unavailable); video optional."
		fi
	else
		echo "SKIP_GST=1 — skipping gstreamer packages."
	fi
}

# ---------- Phase 3: sibling repos ----------
clone_if_absent() {
	local dest="$1"
	local url="$2"
	if [[ -e "${dest}" ]]; then
		echo "skip clone (exists): ${dest}"
		return 0
	fi
	echo "cloning ${url} -> ${dest}"
	mkdir -p "$(dirname "${dest}")"
	git clone --depth 1 "${url}" "${dest}"
}

phase_siblings() {
	log "Phase 3: sibling repositories (idempotent)"

	echo "Expected layout under ${PARENT_DIR}:"
	cat <<'LAYOUT'
  quic-go-prio-packs/
  gst-prio-moq-app/
    priority-moqtransport/
  crypto/                    # from ebpf-go-crypto
  plain-quic-go-lib/
    quic-go/                 # from quic-go-no-crypto
  ebpf-fast-relays/          # this repo
LAYOUT

	clone_if_absent "${PARENT_DIR}/quic-go-prio-packs" \
		"https://github.com/danielpfeifer02/quic-go-prio-packs.git"
	clone_if_absent "${PARENT_DIR}/gst-prio-moq-app" \
		"https://github.com/danielpfeifer02/gst-prio-moq-app.git"
	clone_if_absent "${PARENT_DIR}/gst-prio-moq-app/priority-moqtransport" \
		"https://github.com/danielpfeifer02/priority-moqtransport.git"
	clone_if_absent "${PARENT_DIR}/crypto" \
		"https://github.com/danielpfeifer02/ebpf-go-crypto.git"
	clone_if_absent "${PARENT_DIR}/plain-quic-go-lib/quic-go" \
		"https://github.com/danielpfeifer02/quic-go-no-crypto.git"

	# Ensure libbpf / iproute2 submodules for BPF includes
	cd "${REPO_ROOT}"
	if [[ ! -f "${REPO_ROOT}/libbpf/src/bpf.h" ]] || [[ ! -d "${REPO_ROOT}/iproute2/include" ]]; then
		log "Initializing git submodules (libbpf, iproute2)"
		git submodule update --init --recursive
	else
		echo "submodules libbpf/iproute2: present"
	fi
}

# ---------- Phase 4: netns bridges + connectivity test ----------
phase_bridges() {
	log "Phase 4: namespace bridges + connectivity test"

	[[ -d "${SHELL_DIR}" ]] || die "missing ${SHELL_DIR}"

	# Bridge scripts recreate ns; safe to re-run.
	bash "${SHELL_DIR}/ser-rel-bridge.sh"
	bash "${SHELL_DIR}/rel-cli-bridge.sh"
	bash "${SHELL_DIR}/test-setup.sh"
}

# Prefer clang-14 for TC compile when available (pre-fix workaround).
# After the var_int-by-pointer fix, plain clang 18+ also works.
pick_clang_wrap() {
	local wrap_dir
	wrap_dir="$(mktemp -d /tmp/ebpf-clang-wrap.XXXXXX)"
	if need_cmd clang-14; then
		ln -sf "$(command -v clang-14)" "${wrap_dir}/clang"
		if need_cmd llc-14; then
			ln -sf "$(command -v llc-14)" "${wrap_dir}/llc"
		elif need_cmd llc; then
			ln -sf "$(command -v llc)" "${wrap_dir}/llc"
		fi
		echo "Using clang-14 via ${wrap_dir}" >&2
	else
		need_cmd clang || die "clang not found"
		ln -sf "$(command -v clang)" "${wrap_dir}/clang"
		if need_cmd llc; then
			ln -sf "$(command -v llc)" "${wrap_dir}/llc"
		fi
		echo "Using default clang ($(clang --version 2>/dev/null | head -1)) via ${wrap_dir}" >&2
	fi
	printf '%s' "${wrap_dir}"
}

build_tc_main_objs() {
	# Build the three attachable TC program objects only.
	# (tc_common.c / tc_frame_length_lut.c are #included, not standalone programs.)
	# Attaching via `make tc_main` is left to example execute scripts at runtime.
	make -C "${BPF_DIR}" 		tc/main/tc_ingress_client_side.o 		tc/main/tc_ingress_server_side.o 		tc/main/tc_egress_client_side.o
}

phase_bpf() {
	log "Phase 5: build BPF (TC main objects)"

	need_cmd clang || die "clang not found after apt phase"
	need_cmd llc || die "llc (llvm) not found after apt phase"
	need_cmd make || die "make not found"

	local wrap
	wrap="$(pick_clang_wrap)"
	export PATH="${wrap}:${PATH}"

	set +e
	build_tc_main_objs > /tmp/ebpf_bpf_build.out 2> /tmp/ebpf_bpf_build.err
	local rc=$?
	set -e

	if [[ "${rc}" -ne 0 ]]; then
		if grep -q "stack arguments are not supported" /tmp/ebpf_bpf_build.err /tmp/ebpf_bpf_build.out 2>/dev/null; then
			warn "BPF build failed with clang stack-args error."
			warn "Apply/merge the fix that passes struct var_int by pointer, or install/use clang-14."
			if need_cmd clang-14; then
				ln -sf "$(command -v clang-14)" "${wrap}/clang"
				echo "Retrying with clang-14..."
				build_tc_main_objs || {
					cat /tmp/ebpf_bpf_build.err >&2
					rm -rf "${wrap}"
					die "BPF build still failed after clang-14 retry."
				}
			else
				cat /tmp/ebpf_bpf_build.err >&2
				rm -rf "${wrap}"
				die "BPF build failed (stack arguments). See message above."
			fi
		else
			cat /tmp/ebpf_bpf_build.err >&2
			rm -rf "${wrap}"
			die "BPF build failed. See /tmp/ebpf_bpf_build.err"
		fi
	fi
	echo "BPF TC main objects built under ${BPF_DIR}/tc/main/"
	rm -rf "${wrap}"
}

phase_go() {
	log "Phase 6: build Go examples"

	need_cmd go || die "go toolchain not found"
	export PATH="${PATH}:/usr/local/go/bin"

	mkdir -p "${CHAT_DIR}/build"
	echo "Building priority_drop_chat -> ${CHAT_DIR}/build/main"
	(cd "${CHAT_DIR}" && go build -o build/main ./*.go) \
		|| die "priority_drop_chat build failed (are sibling replace repos present?)"

	if pkg_installed libgstreamer1.0-dev 2>/dev/null || pkg-config --exists gstreamer-1.0 2>/dev/null; then
		mkdir -p "${VIDEO_DIR}/build"
		echo "Building priority_drop_video -> ${VIDEO_DIR}/build/main"
		(cd "${VIDEO_DIR}" && go build -o build/main ./*.go) \
			|| warn "priority_drop_video build failed (gstreamer Go bindings / siblings). Chat binary is ready."
	else
		echo "Skipping priority_drop_video (gstreamer not detected). Install GST packages or unset SKIP_GST."
	fi
}

print_next_steps() {
	log "Done. Next steps"
	cat <<EOF
Namespaces: server_ns, relay_ns, client_ns (bridges v-net-0 / v-net-1).

Enter a namespace and run an example, e.g.:
  sudo ip netns exec relay_ns bash
  cd ${CHAT_DIR} && ./build/main relay

Or use the example start/execute scripts under src/go/examples/.

BPF objects: ${BPF_DIR}/tc/main/*.o
Chat binary:  ${CHAT_DIR}/build/main

Re-run this script anytime; clones are skipped if present, bridges are recreated.
EOF
}

main() {
	echo "ebpf-fast-relays one-shot setup"
	echo "repo: ${REPO_ROOT}"

	phase_checks
	phase_apt
	phase_siblings
	phase_bridges
	phase_bpf
	phase_go
	print_next_steps
}

main "$@"
