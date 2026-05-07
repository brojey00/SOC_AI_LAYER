#!/usr/bin/env python3
"""
Fast streaming conversion: PCAP RAW IP (link-type 12) -> Ethernet (link-type 1).
Prepends a dummy 14-byte Ethernet header to each packet without loading the
full file into memory. Runs orders of magnitude faster than scapy rdpcap().

Usage: python3 convert_pcap.py <input.pcap> <output.pcap>
"""
import sys
import struct

# PCAP global header layout
PCAP_GLOBAL_HEADER_FMT = "IHHiIII"  # magic, ver_maj, ver_min, thiszone, sigfigs, snaplen, network
PCAP_GLOBAL_HEADER_SIZE = struct.calcsize(PCAP_GLOBAL_HEADER_FMT)

# PCAP packet record header
PCAP_PKT_HEADER_FMT = "IIII"  # ts_sec, ts_usec, incl_len, orig_len
PCAP_PKT_HEADER_SIZE = struct.calcsize(PCAP_PKT_HEADER_FMT)

LINK_TYPE_RAW_1   = 12   # Raw IP (OpenBSD)
LINK_TYPE_RAW_2   = 101  # Raw IP (IPv4)
LINK_TYPE_ETHERNET = 1   # Ethernet

# Dummy Ethernet header: src=00:00:00:00:00:00, dst=00:00:00:00:00:00, ethertype=IPv4 (0x0800)
DUMMY_ETH_HEADER = b'\x00' * 12 + b'\x08\x00'
DUMMY_ETH_LEN    = len(DUMMY_ETH_HEADER)  # 14 bytes

def convert(input_path, output_path):
    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        # --- Read & validate global header ---
        raw_global = fin.read(PCAP_GLOBAL_HEADER_SIZE)
        if len(raw_global) < PCAP_GLOBAL_HEADER_SIZE:
            print("[!] File too short to be a valid PCAP.", file=sys.stderr)
            sys.exit(1)

        magic, ver_maj, ver_min, thiszone, sigfigs, snaplen, network = \
            struct.unpack(PCAP_GLOBAL_HEADER_FMT, raw_global)

        # Detect endianness from magic
        if magic == 0xa1b2c3d4:
            endian = "<"
        elif magic == 0xd4c3b2a1:
            endian = ">"
        else:
            print(f"[!] Unrecognised PCAP magic: {magic:#010x}", file=sys.stderr)
            sys.exit(1)

        if network not in (LINK_TYPE_RAW_1, LINK_TYPE_RAW_2, LINK_TYPE_ETHERNET):
            print(f"[!] Unexpected link type {network} — only RAW(12/101) and Ethernet(1) supported.",
                  file=sys.stderr)
            sys.exit(1)

        if network == LINK_TYPE_ETHERNET:
            print(f"[+] Already Ethernet link type — copying as-is.")
            fout.write(raw_global)
            while True:
                chunk = fin.read(65536)
                if not chunk:
                    break
                fout.write(chunk)
            return

        # Rewrite global header with Ethernet link type and enlarged snaplen
        new_snaplen = min(snaplen + DUMMY_ETH_LEN, 65535)
        new_global = struct.pack(
            endian + "IHHiIII",
            magic, ver_maj, ver_min, thiszone, sigfigs, new_snaplen, LINK_TYPE_ETHERNET
        )
        fout.write(new_global)

        # --- Stream packet records ---
        pkt_fmt = endian + PCAP_PKT_HEADER_FMT
        count = 0
        while True:
            raw_pkt_hdr = fin.read(PCAP_PKT_HEADER_SIZE)
            if not raw_pkt_hdr:
                break
            if len(raw_pkt_hdr) < PCAP_PKT_HEADER_SIZE:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(pkt_fmt, raw_pkt_hdr)
            payload = fin.read(incl_len)

            # Write new packet header with Ethernet overhead added
            new_incl_len = incl_len + DUMMY_ETH_LEN
            new_orig_len = orig_len + DUMMY_ETH_LEN
            fout.write(struct.pack(pkt_fmt, ts_sec, ts_usec, new_incl_len, new_orig_len))
            fout.write(DUMMY_ETH_HEADER)
            fout.write(payload)
            count += 1

    print(f"[+] Converted {count} packets  {input_path} -> {output_path}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 convert_pcap.py <input.pcap> <output.pcap>")
        sys.exit(1)
    convert(sys.argv[1], sys.argv[2])
