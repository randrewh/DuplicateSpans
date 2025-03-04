# -*- coding: utf-8 -*-
import ijson
from collections import defaultdict
from datetime import datetime
import sys
from urllib.parse import urlparse

sys.stdout.reconfigure(encoding='utf-8')

if len(sys.argv) < 2:
    print("Usage: python detect_duplicates.py <path_to_trace_file>")
    sys.exit(1)

trace_file = sys.argv[1]

try:
    debug_file = open("debug_log.txt", "w", encoding='utf-8')
except IOError as e:
    print(f"Failed to open debug log file: {e}")
    sys.exit(1)

def debug_log(message):
    try:
        print(f"[DEBUG] {message}", file=debug_file)
        debug_file.flush()
    except Exception as e:
        print(f"Failed to write to debug log file: {e}")

def parse_time(timestamp):
    return datetime.fromtimestamp(timestamp / 1_000_000)

def extract_path_from_url(url):
    parsed_url = urlparse(url)
    return parsed_url.path

def build_span_hierarchy(spans):
    span_dict = {}
    hierarchy = defaultdict(list)
    roots = []
    for span in spans:
        tags = span.get("tags", {})
        if "operationName" not in span or span["operationName"] in ["GET", "POST", "PUT", "DELETE"]:
            method = tags.get("http.request.method") or tags.get("http.method") or "UNKNOWN"
            path = tags.get("url.full") or tags.get("http.target") or tags.get("url.path") or tags.get("http.route")
            if path is None and "http.url" in tags:
                path = extract_path_from_url(tags["http.url"])
            if path is None:
                path = "/*" if "http.method" in tags or "http.request.method" in tags else "Unknown Operation"
            span["operationName"] = f"{method} {path}" if path else span.get("operationName", "Unknown Operation")
        span_dict[span["spanID"]] = span
        debug_log(f"Built span {span['spanID']} with operationName: {span['operationName']}")

    for span in span_dict.values():
        parent_id = None
        refs = span.get("references", [])
        for ref in refs:
            if ref["refType"] == "CHILD_OF" and ref["spanID"] in span_dict:
                parent_id = ref["spanID"]
                hierarchy[parent_id].append(span)
                break
        if not parent_id:
            roots.append(span)

    return span_dict, hierarchy, roots

def get_hierarchy_depth(span_dict, hierarchy, span_id, memo=None):
    if memo is None:
        memo = {}
    if span_id in memo:
        return memo[span_id]
    children = hierarchy.get(span_id, [])
    depth = 0 if not children else 1 + max(get_hierarchy_depth(span_dict, hierarchy, child["spanID"], memo) for child in children)
    memo[span_id] = depth
    return depth

def extract_service_names(span, processes, span_dict):
    tags = span.get("tags", {})
    pid = span.get("processID", "")
    process = processes.get(pid, {}) if pid else {}
    service_name = (
        process.get("serviceName") or
        (process["host.name"].split("-")[0] if "host.name" in process and "sas-" in process["host.name"] else process.get("host.name")) or
        tags.get("messaging.source.name") or
        tags.get("net.host.name") or
        tags.get("user_agent.original", "").split()[-1] if "sas-" in tags.get("user_agent.original", "") else
        "Unknown-Service"
    )
    span_kind = tags.get("span.kind", "client")
    if span_kind == "server":
        requesting = None
        receiving = service_name
        for ref in span.get("references", []):
            if ref["refType"] == "CHILD_OF" and ref["spanID"] in span_dict:
                parent = span_dict[ref["spanID"]]
                parent_pid = parent.get("processID", "")
                parent_process = processes.get(parent_pid, {}) if parent_pid else {}
                parent_service = (
                    parent_process.get("serviceName") or
                    (parent_process["host.name"].split("-")[0] if "host.name" in parent_process and "sas-" in parent_process["host.name"] else parent_process.get("host.name")) or
                    parent.get("tags", {}).get("messaging.source.name") or
                    parent.get("tags", {}).get("net.host.name") or
                    parent.get("tags", {}).get("user_agent.original", "").split()[-1] if "sas-" in parent.get("tags", {}).get("user_agent.original", "") else
                    "Unknown-Parent"
                )
                if parent_service != "Unknown-Service" and parent_service != "Unknown-Parent":
                    requesting = parent_service
                    break
        if not requesting:
            ua = tags.get("user_agent.original", "")
            requesting = ua.split()[-1] if "sas-" in ua else tags.get("net.sock.peer.addr", "Unknown-Client")
    elif span_kind == "consumer":
        requesting = tags.get("messaging.source.name", service_name)
        receiving = service_name
    else:  # client
        requesting = service_name
        receiving = tags.get("server.address", tags.get("net.peer.name", "Unknown-Server"))
    debug_log(f"Extracted service names for span {span.get('spanID', 'unknown')}: requesting={requesting}, receiving={receiving}, processID={pid}, span_kind={span_kind}, tags={tags}")
    return requesting, receiving

def extract_status_code(tags):
    return tags.get("http.response.status_code", tags.get("http.status_code", "N/A"))

def get_parent_id(span):
    refs = span.get("references", [])
    for ref in refs:
        if ref["refType"] == "CHILD_OF":
            return ref["spanID"]
    return None

def is_database_operation(span):
    tags = span.get("tags", {})
    return "db.statement" in tags

def is_leaf_node(span_id, hierarchy):
    return not hierarchy.get(span_id, [])

def get_leaf_spans(span_id, hierarchy, span_dict, leaf_spans=None):
    if leaf_spans is None:
        leaf_spans = []
    children = hierarchy.get(span_id, [])
    if not children:
        leaf_spans.append(span_dict[span_id])
    else:
        for child in children:
            get_leaf_spans(child["spanID"], hierarchy, span_dict, leaf_spans)
    return leaf_spans

def abridge_query(query, max_length=50):
    if len(query) <= max_length:
        return query
    return query[:max_length-3] + "..."

def compare_spans(span1, span2, span_dict, hierarchy, processes, is_top_level=True):
    debug_log(f"Comparing spans {span1['spanID']} and {span2['spanID']} (top_level={is_top_level})")
    is_leaf1 = is_leaf_node(span1["spanID"], hierarchy)
    is_leaf2 = is_leaf_node(span2["spanID"], hierarchy)
    if is_leaf1 and is_leaf2 and is_database_operation(span1) and is_database_operation(span2):
        debug_log(f"Leaf database spans detected, skipping operation name check")
    elif span1["operationName"] != span2["operationName"]:
        debug_log(f"Span operation names do not match: {span1['operationName']} vs {span2['operationName']}")
        return False

    parent_id1 = get_parent_id(span1)
    parent_id2 = get_parent_id(span2)
    if is_top_level and parent_id1 != parent_id2:
        debug_log(f"Top-level span parent IDs do not match: {parent_id1} vs {parent_id2}")
        return False
    
    if is_database_operation(span_dict.get(parent_id1, {})):
        debug_log(f"Parent span is a database operation: {parent_id1}")
        return False
    
    req1, rec1 = extract_service_names(span1, processes, span_dict)
    req2, rec2 = extract_service_names(span2, processes, span_dict)
    if req1 != req2 or rec1 != rec2:
        debug_log(f"Service names do not match: {req1}/{rec1} vs {req2}/{rec2}")
        return False
    
    if abs(span1["startTime"] - span2["startTime"]) > 500_000:
        debug_log(f"Start times do not match within tolerance: {span1['startTime']} vs {span2['startTime']}")
        return False
    
    duration_diff = abs(span1["duration"] - span2["duration"])
    max_duration = max(span1["duration"], span2["duration"])
    if duration_diff > max(100_000, 0.2 * max_duration):
        debug_log(f"Durations do not match within tolerance: {span1['duration']} vs {span2['duration']}")
        return False
    
    children1 = sorted(hierarchy.get(span1["spanID"], []), key=lambda x: (x["operationName"], x["startTime"]))
    children2 = sorted(hierarchy.get(span2["spanID"], []), key=lambda x: (x["operationName"], x["startTime"]))
    debug_log(f"Children of {span1['spanID']}: {[(c['spanID'], get_parent_id(c)) for c in children1]}")
    debug_log(f"Children of {span2['spanID']}: {[(c['spanID'], get_parent_id(c)) for c in children2]}")
    if len(children1) != len(children2):
        debug_log(f"Number of children do not match: {len(children1)} vs {len(children2)}")
        return False
    
    for c1, c2 in zip(children1, children2):
        c1_parent = get_parent_id(c1)
        c2_parent = get_parent_id(c2)
        if c1_parent != span1["spanID"] or c2_parent != span2["spanID"]:
            debug_log(f"Child span parentage inconsistent with top-level span: {c1['spanID']} parent {c1_parent} != {span1['spanID']}, {c2['spanID']} parent {c2_parent} != {span2['spanID']}")
            return False
        if not compare_spans(c1, c2, span_dict, hierarchy, processes, is_top_level=False):
            return False
    return True

def cluster_duplicates(group_spans, span_dict, hierarchy, processes):
    clusters = []
    used = set()
    group_spans.sort(key=lambda x: x["startTime"])
    debug_log(f"Clustering spans for {group_spans[0]['operationName']} with {len(group_spans)} spans: {[s['spanID'] for s in group_spans]}")
    
    for i, span1 in enumerate(group_spans):
        if span1["spanID"] in used:
            continue
        cluster = [span1]
        used.add(span1["spanID"])
        for j in range(i + 1, len(group_spans)):
            span2 = group_spans[j]
            if span2["spanID"] not in used and abs(span1["startTime"] - span2["startTime"]) <= 500_000:
                debug_log(f"Attempting to compare {span1['spanID']} with {span2['spanID']}")
                if compare_spans(span1, span2, span_dict, hierarchy, processes):
                    cluster.append(span2)
                    used.add(span2["spanID"])
        if len(cluster) > 1:
            clusters.append(cluster)
            debug_log(f"Formed initial cluster: {[s['spanID'] for s in cluster]}")
    
    merged_clusters = []
    while clusters:
        current_cluster = clusters.pop(0)
        i = 0
        while i < len(clusters):
            other_cluster = clusters[i]
            should_merge = False
            for span1 in current_cluster:
                for span2 in other_cluster:
                    if abs(span1["startTime"] - span2["startTime"]) <= 500_000:
                        should_merge = True
                        break
                if should_merge:
                    break
            if should_merge:
                current_cluster.extend(clusters.pop(i))
            else:
                i += 1
        merged_clusters.append(current_cluster)
        debug_log(f"Merged cluster: {[s['spanID'] for s in current_cluster]}")
    
    debug_log(f"Clustered {len(merged_clusters)} groups for {group_spans[0]['operationName']}")
    return merged_clusters

def find_duplicate_spans(file_path):
    with open(file_path, "r") as file:
        parser = ijson.parse(file)
        spans = []
        processes = {}
        trace_id = None
        current_span = None
        current_span_tags = []
        current_references = []

        debug_log(f"Starting parsing")

        for prefix, event, value in parser:
            parts = prefix.split(".")
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
                        debug_log(f"Span added: {current_span['spanID']}")
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
                if len(parts) >= 4:
                    pid = parts[3]
                    if pid.startswith("p") and pid[1:].isdigit():
                        if event == "string" and prefix.endswith(".serviceName"):
                            if pid not in processes:
                                processes[pid] = {}
                            processes[pid]["serviceName"] = value

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
            debug_log(f"Span {span['spanID']} grouped with depth: {depth}, operation: {span['operationName']}")

        duplicate_groups = {}
        for key, group in span_groups.items():
            if len(group) > 1 and key[1] >= 1:
                duplicate_groups[key] = cluster_duplicates(group, span_dict, hierarchy, processes)
                if duplicate_groups[key]:
                    debug_log(f"Duplicate groups for {key}: {[(span['spanID'], span['operationName']) for cluster in duplicate_groups[key] for span in cluster]}")

        debug_log(f"Final processes dict: {processes}")
        debug_log(f"Depth map: {depth_map}")
        return duplicate_groups, trace_id, processes, span_dict, hierarchy

def summarize_duplicates(duplicate_groups, trace_id, processes, span_dict, hierarchy):
    debug_log(f"Starting summarize_duplicates with trace_id: {trace_id}, duplicate_groups: {len(duplicate_groups)}")
    lines = [f"\nPotential Duplicate HTTP Span Groups in Trace ID: {trace_id}\n"]
    if not duplicate_groups:
        lines.append("No duplicate HTTP span groups found.")
        debug_log("No duplicate groups found")
        return "\n".join(lines)

    try:
        for (op_name, depth), clusters in sorted(duplicate_groups.items()):
            debug_log(f"Processing operation {op_name} at depth {depth} with {len(clusters)} clusters")
            if len(clusters) == 0:
                debug_log(f"Skipping empty cluster for {op_name} at depth {depth}")
                continue
            parent_span_id = get_parent_id(clusters[0][0]) or "Unknown"
            parent_span = span_dict.get(parent_span_id, {})
            debug_log(f"Parent span ID: {parent_span_id}, span data: {parent_span}")
            parent_requesting, parent_receiving = extract_service_names(parent_span, processes, span_dict)
            parent_request = parent_span.get("operationName", "Unknown")
            
            lines.append(f"Parent Service Name: {parent_requesting}")
            lines.append(f"Parent HTTP Request: {parent_request}")
            lines.append(f"Parent Span ID: {parent_span_id}")
            lines.append(f"Operation Name: {op_name} with Hierarchy Depth: {depth}")
            lines.append(f"Duplicate Cluster Count: {len(clusters)}\n")
            
            for i, cluster in enumerate(clusters[:10], 1):
                debug_log(f"Processing cluster {i} with first span: {cluster[0]['spanID']}")
                requesting, receiving = extract_service_names(cluster[0], processes, span_dict)
                debug_log(f"Cluster {i} assigned: requesting={requesting}, receiving={receiving}")
                lines.append(f"Cluster {i} -- Requesting Service: {requesting}, Receiving Service: {receiving} (Size: {len(cluster)}):")
                sorted_cluster = sorted(cluster, key=lambda x: x["startTime"])
                for j, span in enumerate(sorted_cluster[:5], 1):
                    start_time = parse_time(span["startTime"])
                    duration = span["duration"]
                    status_code = extract_status_code(span["tags"])
                    lines.extend([
                        f"  Span {j} - ID: {span['spanID']}, Start Time: {start_time}, Duration: {duration} microseconds, HTTP Status Code: {status_code}"
                    ])
                if len(cluster) > 5:
                    lines.append(f"    ...and {len(cluster) - 5} more spans")
                
                leaf_spans = get_leaf_spans(sorted_cluster[0]["spanID"], hierarchy, span_dict)
                if leaf_spans:
                    leaf = leaf_spans[0]
                    if is_database_operation(leaf):
                        query = leaf["tags"].get("db.statement", "Unknown Query")
                        lines.append(f"  Last Generation DB Query: {abridge_query(query)}")
                    else:
                        lines.append(f"  Last Generation HTTP Request: {leaf['operationName']}")
                else:
                    lines.append("  Last Generation: None")
                lines.append("")
            
            lines.append("-" * 40)
    except Exception as e:
        debug_log(f"Exception in summarize_duplicates: {str(e)}")
        raise

    debug_log("Finished summarize_duplicates")
    return "\n".join(lines)

if __name__ == "__main__":
    try:
        debug_log("Starting main execution")
        duplicate_groups, trace_id, processes, span_dict, hierarchy = find_duplicate_spans(trace_file)
        debug_log("Calling summarize_duplicates")
        result = summarize_duplicates(duplicate_groups, trace_id, processes, span_dict, hierarchy)
        print(result)
        debug_log("Main execution completed")
    except Exception as e:
        debug_log(f"Error in main: {str(e)}")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        debug_file.close()
