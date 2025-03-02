# -*- coding: utf-8 -*-
import ijson
from collections import defaultdict
from datetime import datetime
import sys

sys.stdout.reconfigure(encoding='utf-8')

if len(sys.argv) < 2:
    print("Usage: python test.py <path_to_trace_file>")
    sys.exit(1)

trace_file = sys.argv[1]

debug_file = open("debug_log.txt", "w", encoding='utf-8')

def debug_log(message):
    print(f"[DEBUG] {message}", file=debug_file)

def parse_time(timestamp):
    return datetime.fromtimestamp(timestamp / 1_000_000)

def build_span_hierarchy(spans):
    span_dict = {}
    hierarchy = defaultdict(list)
    roots = []
    for span in spans:
        tags = span.get("tags", {})
        if "http.request.method" not in tags and "db.statement" not in tags:
            debug_log(f"Skipping non-HTTP/DB span {span['spanID']}")
            continue
        if "http.request.method" in tags:
            method = tags["http.request.method"]
            path = tags.get("http.target", tags.get("url.path", tags.get("http.route", "/*")))
            span["operationName"] = f"{method} {path}"
        else:
            span["operationName"] = span.get("operationName", "UNKNOWN")
        debug_log(f"Span {span['spanID']} operationName set to: {span['operationName']}")
        span_dict[span["spanID"]] = span

    for span in span_dict.values():
        parent_id = None
        refs = span.get("references", [])
        debug_log(f"Span {span['spanID']} references: {refs}")
        for ref in refs:
            if ref["refType"] == "CHILD_OF" and ref["spanID"] in span_dict:
                parent_id = ref["spanID"]
                hierarchy[parent_id].append(span)
                debug_log(f"Linked {span['spanID']} as child of {parent_id}")
                break
        if not parent_id:
            roots.append(span)
            debug_log(f"Root span {span['spanID']}")

    return span_dict, hierarchy, roots

def get_hierarchy_depth(span_dict, hierarchy, span_id, memo=None):
    if memo is None:
        memo = {}
    if span_id in memo:
        return memo[span_id]
    children = hierarchy.get(span_id, [])
    depth = 0 if not children else 1 + max(get_hierarchy_depth(span_dict, hierarchy, child["spanID"], memo) for child in children)
    memo[span_id] = depth
    debug_log(f"Span {span_id} depth: {depth}, children: {[child['spanID'] for child in children]}")
    return depth

def extract_service_names(span, processes, span_dict):
    tags = span.get("tags", {})
    pid = span.get("processID", "")
    process = processes.get(pid, {})
    debug_log(f"Span {span['spanID']} process lookup for {pid}: {process}")
    service_name = process.get("serviceName")
    if not service_name and "host.name" in process:
        service_name = process["host.name"].split("-")[0] if "sas-" in process["host.name"] else process["host.name"]
    service_name = service_name or "Unknown"
    debug_log(f"Span {span['spanID']} service_name resolved to: {service_name}")
    span_kind = tags.get("span.kind", "client")
    if span_kind == "server":
        requesting = "Unknown"
        receiving = service_name
        for ref in span.get("references", []):
            if ref["refType"] == "CHILD_OF" and ref["spanID"] in span_dict:
                parent = span_dict[ref["spanID"]]
                parent_pid = parent.get("processID", "")
                parent_process = processes.get(parent_pid, {})
                debug_log(f"Span {span['spanID']} parent {ref['spanID']} process lookup for {parent_pid}: {parent_process}")
                parent_service = parent_process.get("serviceName")
                if not parent_service and "host.name" in parent_process:
                    parent_service = parent_process["host.name"].split("-")[0] if "sas-" in parent_process["host.name"] else parent_process["host.name"]
                if parent_service and parent_service != "Unknown":
                    requesting = parent_service
                elif "user_agent.original" in parent["tags"]:
                    ua = parent["tags"]["user_agent.original"]
                    requesting = ua.split()[-1] if "sas-" in ua else requesting
                debug_log(f"Span {span['spanID']} parent requesting resolved to: {requesting}")
                break
        if requesting == "Unknown":
            requesting = tags.get("net.sock.peer.addr", tags.get("net.peer.ip", "Unknown"))
    else:
        requesting = service_name
        receiving = tags.get("server.address", tags.get("net.peer.name", "Unknown"))
    debug_log(f"Span {span['spanID']} - Requesting: {requesting}, Receiving: {receiving}, Kind: {span_kind}")
    return requesting, receiving

def extract_status_code(tags):
    return tags.get("http.response.status_code", tags.get("http.status_code", "N/A"))

def compare_spans(span1, span2, span_dict, hierarchy):
    if span1["operationName"] != span2["operationName"]:
        return False
    req1, rec1 = extract_service_names(span1, {}, span_dict)
    req2, rec2 = extract_service_names(span2, {}, span_dict)
    if req1 != req2 or rec1 != rec2:
        return False
    if abs(span1["startTime"] - span2["startTime"]) > 50_000:
        return False
    if abs(span1["duration"] - span2["duration"]) > 0.1 * max(span1["duration"], span2["duration"]):
        return False
    children1 = sorted(hierarchy.get(span1["spanID"], []), key=lambda x: x["spanID"])
    children2 = sorted(hierarchy.get(span2["spanID"], []), key=lambda x: x["spanID"])
    if len(children1) != len(children2):
        return False
    return all(compare_spans(c1, c2, span_dict, hierarchy) for c1, c2 in zip(children1, children2))

def cluster_duplicates(group_spans, span_dict, hierarchy):
    clusters = []
    used = set()
    for i, span1 in enumerate(group_spans):
        if span1["spanID"] in used:
            continue
        cluster = [span1]
        used.add(span1["spanID"])
        for span2 in group_spans[i+1:]:
            if span2["spanID"] not in used and compare_spans(span1, span2, span_dict, hierarchy):
                cluster.append(span2)
                used.add(span2["spanID"])
        if len(cluster) > 1:
            clusters.append(cluster)
    debug_log(f"Clustered {len(clusters)} groups for {group_spans[0]['operationName']}")
    return clusters

def find_duplicate_spans(file_path):
    with open(file_path, "r") as file:
        parser = ijson.parse(file)
        spans = []
        processes = {}
        trace_id = None
        current_span = None
        current_span_tags = []
        current_references = []

        debug_log(f"Starting parsing, processes: {processes}")

        for prefix, event, value in parser:
            debug_log(f"Parsing: {prefix}, {event}, {value}, processes: {processes}")
            parts = prefix.split(".")
            debug_log(f"Parts: {parts}")

            if prefix == "data.item.traceID" and event == "string":
                trace_id = value
                debug_log(f"Trace ID: {trace_id}")

            elif prefix == "data.item.spans.item" and event == "start_map":
                current_span = {"tags": {}, "references": []}
                current_span_tags = []
                current_references = []

            elif prefix == "data.item.spans.item" and event == "end_map":
                if current_span:
                    current_span["tags"] = {tag["key"]: tag["value"] for tag in current_span_tags if "key" in tag and "value" in tag}
                    current_span["references"] = current_references
                    if "spanID" in current_span and "startTime" in current_span and "duration" in current_span:
                        spans.append(current_span)
                        debug_log(f"Span added: {current_span}")
                    current_span = None
                    current_span_tags = []
                    current_references = []

            elif prefix == "data.item.spans.item.tags.item" and event == "start_map":
                current_span_tags.append({})
            elif prefix.endswith(".key") and event in ("string", "number") and current_span_tags:
                current_span_tags[-1]["key"] = str(value).replace("http.method", "http.request.method")
            elif prefix.endswith(".value") and event in ("string", "number") and current_span_tags:
                current_span_tags[-1]["value"] = str(value)

            elif prefix == "data.item.spans.item.references.item" and event == "start_map":
                current_references.append({})
            elif prefix.endswith(".refType") and current_references:
                current_references[-1]["refType"] = value
            elif prefix.endswith(".spanID") and event == "string":
                if current_references:
                    current_references[-1]["spanID"] = value
                elif prefix == "data.item.spans.item.spanID":
                    current_span["spanID"] = value

            elif current_span and event in ("string", "number"):
                if prefix == "data.item.spans.item.operationName":
                    current_span["operationName"] = value
                elif prefix == "data.item.spans.item.startTime":
                    current_span["startTime"] = int(value)
                elif prefix == "data.item.spans.item.duration":
                    current_span["duration"] = int(value)
                elif prefix == "data.item.spans.item.processID":
                    current_span["processID"] = value

            elif prefix.startswith("data.item.processes"):
                if len(parts) >= 3:
                    pid = parts[2]
                    debug_log(f"Checking pid: {pid}")
                    if pid.startswith("p") and pid[1:].isdigit():
                        debug_log(f"Valid pid: {pid}")
                        if event == "string" and prefix.endswith(".serviceName"):
                            debug_log(f"ServiceName detected for {pid}")
                            processes[pid] = {"serviceName": value}
                            debug_log(f"Set {pid} serviceName to: {value}")

        if not spans or not trace_id:
            debug_log(f"Spans: {len(spans)}, Trace ID: {trace_id}")
            print("No valid spans or trace ID found.")
            sys.exit(1)

        span_dict, hierarchy, roots = build_span_hierarchy(spans)
        span_groups = defaultdict(list)
        depth_map = {}
        for span in span_dict.values():
            depth = get_hierarchy_depth(span_dict, hierarchy, span["spanID"])
            depth_map[span["spanID"]] = depth
            span_groups[(span["operationName"], depth)].append(span)
            debug_log(f"Span {span['spanID']} grouped with depth: {depth}")

        duplicate_groups = {}
        for key, group in span_groups.items():
            if len(group) > 1:
                duplicate_groups[key] = cluster_duplicates(group, span_dict, hierarchy)

        debug_log(f"Final processes dict: {processes}")
        debug_log(f"Depth map: {depth_map}")
        return duplicate_groups, trace_id, processes, span_dict

def summarize_duplicates(duplicate_groups, trace_id, processes, span_dict):
    lines = [f"\nPotential Duplicate HTTP Span Groups in Trace ID: {trace_id}\n"]
    if not duplicate_groups:
        lines.append("No duplicate HTTP span groups found.")
        return "\n".join(lines)

    for (op_name, depth), clusters in sorted(duplicate_groups.items()):
        lines.append(f"Operation Name: {op_name} with Hierarchy Depth: {depth}")
        lines.append(f"Duplicate Cluster Count: {len(clusters)}\n")
        for i, cluster in enumerate(clusters[:10], 1):
            lines.append(f"Cluster {i} (Size: {len(cluster)}):")
            for j, span in enumerate(cluster[:5], 1):
                req, rec = extract_service_names(span, processes, span_dict)
                lines.extend([
                    f"  Span {j} - ID: {span['spanID']}",
                    f"    Requesting Service: {req}",
                    f"    Receiving Service: {rec}",
                    f"    Start Time: {parse_time(span['startTime'])}",
                    f"    Duration: {span['duration']} microseconds",
                    f"    HTTP Status Code: {extract_status_code(span['tags'])}"
                ])
            if len(cluster) > 5:
                lines.append(f"    ...and {len(cluster) - 5} more spans")
            lines.append("")
        lines.append("-" * 40)

    return "\n".join(lines)

if __name__ == "__main__":
    try:
        duplicate_groups, trace_id, processes, span_dict = find_duplicate_spans(trace_file)
        print(summarize_duplicates(duplicate_groups, trace_id, processes, span_dict))
    except Exception as e:
        debug_log(f"Error: {str(e)}")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        debug_file.close()