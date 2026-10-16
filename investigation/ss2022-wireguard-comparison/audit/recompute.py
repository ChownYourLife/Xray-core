#!/usr/bin/env python3
"""Independently recompute the SS2022/WireGuard supplement from raw timing samples."""
import hashlib
import json
import math
import statistics
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT.parent / "transport-e2e-comparison"
VARIANTS = ("official", "original-gso", "batching-only", "hybrid")
CASE = "ss2022-wireguard"
TCP_BYTES = 128 * 1024 * 1024
UDP_BYTES = (16 * 1024 * 1024 // (32 * 1200)) * (32 * 1200)
UDP_DATAGRAMS = UDP_BYTES // 1200


def read_json(path):
    return json.loads(path.read_text())


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def stats(values):
    median = statistics.median(values)
    q1, _, q3 = statistics.quantiles(values, n=4, method="inclusive")
    return {
        "n": len(values), "median": median, "q1": q1, "q3": q3,
        "min": min(values), "max": max(values),
        "mad": statistics.median(abs(value - median) for value in values),
        "round_values": values,
    }


def old_udp_environment():
    archive = BASELINE / "udp-cohort-lossaware-v1/raw.tar.gz"
    with tarfile.open(archive, "r:gz") as source:
        return json.load(source.extractfile("udp-cohort-lossaware-v1/environment.json"))


def accepted_environments():
    return {
        "tcp": read_json(BASELINE / "tcp-cohort-v2/timing-tcp-v2/environment.json"),
        "udp": old_udp_environment(),
    }


def check_equal(actual, expected, where):
    if actual != expected:
        raise ValueError(f"{where}: {actual!r} != {expected!r}")


def process_contract(sample, network, variant, round_key):
    processes = {item["role"]: item for item in sample["processes"]}
    check_equal(set(processes), {"client", "relay", "gateway"}, f"{round_key} process roles")
    expected = {
        "client": ([0, 1], "hybrid", "ss2022-wireguard-client.json"),
        "gateway": ([0, 1], "hybrid", "gateway.json"),
        "relay": ([2, 3], variant, "ss2022-wireguard-relay.json"),
    }
    for role, (cpus, binary, config) in expected.items():
        record = processes[role]
        check_equal(record["requested_cpus"], "0,1" if cpus == [0, 1] else "2,3", f"{round_key} {role} requested CPU")
        check_equal(record["GOMAXPROCS"], 2, f"{round_key} {role} GOMAXPROCS")
        check_equal(record["observed_affinity"], cpus, f"{round_key} {role} observed affinity")
        argv = record["argv"]
        check_equal(argv[:3], ["taskset", "-c", "0,1" if cpus == [0, 1] else "2,3"], f"{round_key} {role} taskset")
        if not argv[3].endswith("/binaries/" + binary) or not argv[-1].endswith("/configs/" + config):
            raise ValueError(f"{round_key} {role} binary/config path mismatch: {argv}")

def derive(network, raw_root, accepted_env):
    index = read_json(raw_root / "index.json")
    closure = read_json(raw_root / "closure.json")
    check_equal(closure, {**closure, "completed_cells": 28, "expected_cells": 28, "all_passed": True}, f"{network} closure")
    check_equal(len(index), 28, f"{network} index size")
    check_equal(len(list(raw_root.glob("r*/sample.json"))), 28, f"{network} raw sample file count")
    expected = {(round_no, variant) for round_no in range(1, 8) for variant in VARIANTS}
    indexed = {(item["round"], item["variant"]) for item in index}
    check_equal(indexed, expected, f"{network} index matrix")
    environment = read_json(raw_root / "environment.json")
    check_equal(environment["cohort"], "separately-collected-ss2022-wireguard-supplement", f"{network} cohort")
    check_equal(environment["phase"], "timing", f"{network} phase")
    check_equal(environment["network"], network, f"{network} environment")
    check_equal(environment["round_orders"], accepted_env["round_orders"], f"{network} round order")
    check_equal(environment["assignments"]["relay"], {"cpus": [2, 3], "GOMAXPROCS": 2}, f"{network} relay assignment")
    check_equal(environment["assignments"]["fixed_support"], {"cpus": [0, 1], "GOMAXPROCS": 2}, f"{network} fixed support assignment")
    pin_names = ("binaries/application", "binaries/official", "binaries/original-gso", "binaries/batching-only", "binaries/hybrid", "configs/gateway.json")
    pin_checks = {name: environment["pins"].get(name) == accepted_env["pins"].get(name) for name in pin_names}
    if not all(pin_checks.values()):
        raise ValueError(f"{network} frozen binary/gateway pin mismatch: {pin_checks}")
    groups = {variant: [] for variant in VARIANTS}
    hashes = {}
    aggregate = {"directional_transfers": 0, "offered_datagrams": 0, "unique_verified_datagrams": 0, "lost_datagrams": 0, "duplicate_datagrams": 0, "corrupt_datagrams": 0, "delivered_payload_bytes": 0, "data_retransmissions": 0}
    for item in sorted(index, key=lambda row: (row["round"], VARIANTS.index(row["variant"]))):
        round_no, variant = item["round"], item["variant"]
        rel = f"r{round_no:02d}-{CASE}-{network}-{variant}/sample.json"
        path = raw_root / rel
        raw = path.read_bytes()
        sample = json.loads(raw)
        key = (round_no, variant)
        check_equal((sample["phase"], sample["round"], sample["case"], sample["network"], sample["variant"], sample["status"]), ("timing", round_no, CASE, network, variant, "passed"), f"{network} cell {key}")
        check_equal(item["status"], "passed", f"{network} index {key} status")
        check_equal(sample["application"]["exit"], 0, f"{network} application exit {key}")
        process_contract(sample, network, variant, f"{network} cell {key}")
        s = sample["application"]["sample"]
        check_equal(len(s["established_rtt_ns"]), 256, f"{network} RTT sample count {key}")
        check_equal(len(s["setup_first_response_ns"]), 8, f"{network} setup sample count {key}")
        if not all(type(value) is int and value > 0 for name in ("established_rtt_ns", "setup_first_response_ns") for value in s[name]):
            raise ValueError(f"{network} nonpositive/noninteger latency sample {key}")
        result = {
            "round": round_no,
            "source": rel,
            "established_rtt_round_median_ns": statistics.median(s["established_rtt_ns"]),
            "setup_first_response_round_median_ns": statistics.median(s["setup_first_response_ns"]),
        }
        transfers = {transfer["direction"]: transfer for transfer in s["transfers"]}
        check_equal(set(transfers), {"upload", "download"}, f"{network} directions {key}")
        for direction, transfer in transfers.items():
            duration = transfer["receiver_duration_ns"]
            if type(duration) is not int or duration <= 0:
                raise ValueError(f"{network} invalid receiver duration {key} {direction}")
            if not transfer.get("verified_all_received_bytes", transfer.get("verified_all_counted_bytes", False)):
                raise ValueError(f"{network} receiver did not verify all counted bytes {key} {direction}")
            if network == "tcp":
                check_equal(transfer["delivered_bytes"], TCP_BYTES, f"TCP bytes {key} {direction}")
                check_equal(transfer["stream_count"], 1, f"TCP stream count {key} {direction}")
            else:
                check_equal(transfer["offered_bytes"], UDP_BYTES, f"UDP offered bytes {key} {direction}")
                check_equal(transfer["offered_datagrams"], UDP_DATAGRAMS, f"UDP offered datagrams {key} {direction}")
                check_equal(transfer["payload_bytes_per_datagram"], 1200, f"UDP payload bytes {key} {direction}")
                check_equal(transfer["application_window_datagrams"], 32, f"UDP window {key} {direction}")
                check_equal(transfer["drain_bound_ns"], 100_000_000, f"UDP drain {key} {direction}")
                check_equal(transfer["final_receiver_counters_via_reliable_control"], True, f"UDP reliable counters {key} {direction}")
                check_equal(transfer["offered_datagrams"], transfer["unique_verified_datagrams"] + transfer["lost_datagrams"], f"UDP count identity {key} {direction}")
                check_equal(transfer["delivered_bytes"], transfer["unique_verified_datagrams"] * 1200, f"UDP payload identity {key} {direction}")
                check_equal(transfer["retransmissions"], 0, f"UDP data retransmissions {key} {direction}")
                check_equal(transfer["verified_all_counted_bytes"], True, f"UDP final counter verification {key} {direction}")
                for name in ("offered_datagrams", "unique_verified_datagrams", "lost_datagrams", "duplicate_datagrams", "corrupt_datagrams"):
                    aggregate[name] += transfer.get(name, 0)
                
                aggregate["data_retransmissions"] += transfer.get("retransmissions", 0)
            aggregate["delivered_payload_bytes"] += transfer["delivered_bytes"]
            result[direction + "_MB_s"] = transfer["delivered_bytes"] * 1000 / duration
            result[direction + "_Mbit_s"] = result[direction + "_MB_s"] * 8
            if network == "udp":
                result[direction + "_lost_datagrams"] = transfer["lost_datagrams"]
                result[direction + "_duplicate_datagrams"] = transfer["duplicate_datagrams"]
                result[direction + "_corrupt_datagrams"] = transfer["corrupt_datagrams"]
                result[direction + "_offered_bytes"] = transfer["offered_bytes"]
                result[direction + "_delivered_bytes"] = transfer["delivered_bytes"]
                result[direction + "_loss_percent"] = 100 * transfer["lost_datagrams"] / transfer["offered_datagrams"]
            aggregate["directional_transfers"] += 1
        groups[variant].append(result)
        hashes[rel] = sha256(raw)
    results = []
    for variant in VARIANTS:
        rounds = groups[variant]
        check_equal([row["round"] for row in rounds], list(range(1, 8)), f"{network} {variant} round order")
        result = {"case": CASE, "network": network, "variant": variant, "rounds": rounds}
        for name in rounds[0]:
            if name not in ("round", "source"):
                result[name] = stats([row[name] for row in rounds])
        result["established_rtt_us"] = stats([row["established_rtt_round_median_ns"] / 1000 for row in rounds])
        result["setup_first_response_us"] = stats([row["setup_first_response_round_median_ns"] / 1000 for row in rounds])
        results.append(result)
    return {
        "network": network, "cells": 28, "matched_rounds": 7,
        "primary_summary": "Median of seven per-round values; latency is median of per-round medians, not pooled raw samples.",
        "dispersion": "Inclusive linear Q1/Q3 and median absolute deviation over seven round values.",
        "environment_pin_matches_accepted_protocol": pin_checks,
        "environment_sha256": sha256((raw_root / "environment.json").read_bytes()),
        "source_sample_sha256": hashes,
        "aggregates": aggregate,
        "groups": results,
    }


def compare_group(independent, reported, mismatches, numeric_count, omissions):
    for field, expected in independent.items():
        if field in ("case", "network", "variant"):
            if reported.get(field) != expected:
                mismatches.append({"key": [independent["case"], independent["network"], independent["variant"]], "field": field, "expected": expected, "reported": reported.get(field)})
        elif field == "rounds":
            if len(reported.get("rounds", [])) != len(expected):
                mismatches.append({"key": [independent["case"], independent["network"], independent["variant"]], "field": "rounds.length", "expected": len(expected), "reported": len(reported.get("rounds", []))})
                continue
            for i, row in enumerate(expected):
                other = reported["rounds"][i]
                for name, value in row.items():
                    if name == "source":
                        continue
                    actual = other.get(name)
                    if name.endswith("_corrupt_datagrams") and actual is None and value == 0:
                        omission = {"key": [independent["case"], independent["network"], independent["variant"]], "field": name, "omitted_but_all_raw_values_zero": True}
                        if omission not in omissions:
                            omissions.append(omission)
                        continue
                    numeric_count[0] += 1
                    if not isinstance(actual, (int, float)) or not math.isclose(value, actual, rel_tol=1e-12, abs_tol=1e-12):
                        mismatches.append({"key": [independent["case"], independent["network"], independent["variant"], row["round"]], "field": name, "independent": value, "reported": actual})
        elif isinstance(expected, dict) and "median" in expected:
            actual_stats = reported.get(field, {})
            if field.endswith("_corrupt_datagrams") and not actual_stats and all(value == 0 for value in expected["round_values"]):
                omission = {"key": [independent["case"], independent["network"], independent["variant"]], "field": field, "omitted_but_all_raw_values_zero": True}
                if omission not in omissions:
                    omissions.append(omission)
                continue
            for name in ("n", "median", "q1", "q3", "min", "max", "mad"):
                numeric_count[0] += 1
                value, actual = expected[name], actual_stats.get(name)
                if not isinstance(actual, (int, float)) or not math.isclose(value, actual, rel_tol=1e-12, abs_tol=1e-12):
                    mismatches.append({"key": [independent["case"], independent["network"], independent["variant"]], "field": field + "." + name, "independent": value, "reported": actual})


def main():
    accepted = accepted_environments()
    tcp = derive("tcp", ROOT / "timing-tcp/timing-tcp", accepted["tcp"])
    udp = derive("udp", ROOT / "timing-udp/timing-udp", accepted["udp"])
    independently_recomputed = {"scope": "raw supplement timing samples; separate cohort", "tcp": tcp, "udp": udp}
    result_path = ROOT / "audit/independent-results.json"
    result_path.write_text(json.dumps(independently_recomputed, indent=2) + "\n")
    # Producer summaries are opened only after the independent raw-derived output is durable.
    mismatches = []
    compared = [0]
    omissions = []
    for network, independent in (("tcp", tcp), ("udp", udp)):
        reported = read_json(ROOT / f"summary-{network}.json")
        check_equal(reported["network"], network, f"reported {network} summary network")
        check_equal(reported["cells"], 28, f"reported {network} summary cell count")
        check_equal(reported["matched_rounds"], 7, f"reported {network} summary rounds")
        check_equal(reported["source_sample_sha256"], independent["source_sample_sha256"], f"reported {network} source sample hashes")
        by_variant = {group["variant"]: group for group in reported["groups"]}
        check_equal(set(by_variant), set(VARIANTS), f"reported {network} group variants")
        for result in independent["groups"]:
            compare_group(result, by_variant[result["variant"]], mismatches, compared, omissions)
    reconciliation = {
        "scope": "Independent raw recomputation then numeric comparison against executor summaries",
        "raw_cells": {"tcp": 28, "udp": 28, "total": 56},
        "groups": {"tcp": 4, "udp": 4, "total": 8},
        "compared_numeric_values": compared[0],
        "producer_summary_omissions": omissions,
        "result": "match" if not mismatches else "mismatch",
        "independent_result": "audit/independent-results.json",
    }
    (ROOT / "audit/reconciliation.json").write_text(json.dumps(reconciliation, indent=2) + "\n")
    if mismatches:
        raise SystemExit(f"{len(mismatches)} executor summary mismatches; see audit/reconciliation.json")


if __name__ == "__main__":
    main()
