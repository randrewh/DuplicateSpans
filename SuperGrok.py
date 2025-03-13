# -*- coding: utf-8 -*-
import ijson
from collections import defaultdict, Counter
from datetime import datetime
import sys
from urllib.parse import urlparse
import json
import uuid

sys.stdout.reconfigure(encoding='utf-8')

# Define debug_log early
debug_file = open("debug_log.txt", "w", encoding='utf-8')
def debug_log(message):
    print(f"[DEBUG] {message}", file=debug_file)

if len(sys.argv) < 2:
    print("Usage: python SuperGrok.py <path_to_trace_file> [start_difference=ms] [gap_difference=ms]")
    print("Example: python SuperGrok.py trace.json start_difference=1000 gap_difference=-200")
    sys.exit(1)

trace_file = sys.argv[1]
start_difference = 500000  # Default 500 ms in microseconds
gap_difference = 150000    # Default 150 ms in microseconds

# Parse keyword arguments with =
for arg in sys.argv[2:]:
    try:
        if arg.startswith("start_difference="):
            start_difference = int(float(arg.split("=")[1]) * 1000)  # Convert ms to us
            debug_log(f"Set start_difference to {start_difference} us")
        elif arg.startswith("gap_difference="):
            gap_difference = int(float(arg.split("=")[1]) * 1000)  # Convert ms to us
            debug_log(f"Set gap_difference to {gap_difference} us")
        else:
            print(f"Warning: Ignoring unrecognized argument '{arg}'. Use start_difference=nnn or gap_difference=nnnn")
    except (ValueError, IndexError):
        print(f"Error: Invalid value in '{arg}'. Use like: start_difference=1000 or gap_difference=-200")
        sys.exit(1)

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
        operation_name = span.get("operationName", "UNKNOWN")
        
        if "http.request.method" in tags or "http.method" in tags:
            method = tags.get("http.request.method") or tags.get("http.method")
            path = tags.get("http.target") or tags.get("url.path") or tags.get("http.route") or tags.get("url.full") or None
            if path is None and "http.url" in tags:
                path = extract_path_from_url(tags["http.url"])
            if path is None:
                path = "/*"
            operation_name = f"{method} {path}"
        elif "db.statement" in tags:
            db_statement = tags.get("db.statement")
            db_table = tags.get("db.sql.table", "unknown_table")
            if db_statement.startswith("SELECT"):
                operation_name = f"SELECT {db_table}"
            elif db_statement.startswith("INSERT"):
                operation_name = f"INSERT {db_table}"
            elif db_statement.startswith("UPDATE"):
                operation_name = f"UPDATE {db_table}"
            elif db_statement.startswith("DELETE"):
                operation_name = f"DELETE {db_table}"
            else:
                operation_name = f"QUERY {db_table}"
        span["operationName"] = operation_name
        debug_log(f"Span {span['spanID']} operationName finalized: {operation_name}")
        span_dict[span["spanID"]] = span

    for span in span_dict.values():
        parent_id = None
        refs = span.get("references", [])
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
    depth = 0 if not children else 1 + max((get_hierarchy_depth(span_dict, hierarchy, child["spanID"], memo) for child in children), default=0)
    memo[span_id] = depth
    debug_log(f"Span {span_id} depth: {depth}, children: {[child['spanID'] for child in children]}")
    return depth

def count_total_spans(span, hierarchy):
    kids = hierarchy.get(span["spanID"], [])
    total = 1  # Count the span itself
    for child in kids:
        total += count_total_spans(child, hierarchy)
    return total

def is_db_span(span):
    return "db.statement" in span.get("tags", {})

def extract_service_names(span, processes, span_dict):
    tags = span.get("tags", {})
    pid = span.get("processID", "")
    process = processes.get(pid, {})
    service_name = process.get("serviceName") or "Unknown"
    span_kind = tags.get("span.kind", "client")
    if span_kind == "server":
        requesting = "Unknown"
        receiving = service_name
        for ref in span.get("references", []):
            if ref["refType"] == "CHILD_OF" and ref["spanID"] in span_dict:
                parent = span_dict[ref["spanID"]]
                parent_pid = parent.get("processID", "")
                parent_process = processes.get(parent_pid, {})
                requesting = parent_process.get("serviceName") or "Unknown"
                break
    else:
        requesting = service_name
        receiving = tags.get("server.address")
        if not receiving and "http.url" in tags:
            parsed_url = urlparse(tags["http.url"])
            receiving = parsed_url.hostname or "Unknown"
        if not receiving:
            receiving = tags.get("net.peer.name", "Unknown")
        for server_span in span_dict.values():
            if server_span.get("spanID") == span["spanID"]:
                continue
            refs = server_span.get("references", [])
            if any(ref["spanID"] == span["spanID"] and ref["refType"] == "CHILD_OF" for ref in refs):
                server_pid = server_span.get("processID", "")
                server_service = processes.get(server_pid, {}).get("serviceName", receiving)
                receiving = server_service
                debug_log(f"Span {span['spanID']} - Overrode receiving to server span {server_span['spanID']} service: {receiving}")
                break
    debug_log(f"Span {span['spanID']} - Requesting: {requesting}, Receiving: {receiving}, Kind: {span_kind}, URL: {tags.get('http.url', 'N/A')}")
    return requesting, receiving

def extract_status_code(tags):
    return tags.get("http.response.status_code", tags.get("http.status_code", "N/A"))

def compare_subtrees(span1, span2, span_dict, hierarchy, processes, depth):
    debug_log(f"Comparing spans {span1['spanID']} vs {span2['spanID']} at depth {depth}")
    children1 = sorted(hierarchy.get(span1["spanID"], []), key=lambda x: x["operationName"])
    children2 = sorted(hierarchy.get(span2["spanID"], []), key=lambda x: x["operationName"])
    
    # Check processID to ensure same requesting service
    process_id1 = span1.get("processID", None)
    process_id2 = span2.get("processID", None)
    if process_id1 != process_id2:
        service1 = processes.get(process_id1, {}).get("serviceName", "Unknown")
        service2 = processes.get(process_id2, {}).get("serviceName", "Unknown")
        debug_log(f"Span {span1['spanID']} (service: {service1}) vs {span2['spanID']} (service: {service2}) - processID mismatch")
        return False
    
    def get_max_depth(span_id, current_depth=0):
        kids = hierarchy.get(span_id, [])
        if not kids:
            return current_depth
        return max(get_max_depth(k["spanID"], current_depth + 1) for k in kids)
    
    depth1 = get_max_depth(span1["spanID"])
    depth2 = get_max_depth(span2["spanID"])
    debug_log(f"Depth check: {span1['spanID']} depth {depth1}, {span2['spanID']} depth {depth2}")
    if depth == 0 and (depth1 < 2 or depth2 < 2 or depth1 != depth2):
        debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - root depth mismatch or < 2: {depth1} vs {depth2}")
        return False
    
    span_count1 = count_total_spans(span1, hierarchy)
    span_count2 = count_total_spans(span2, hierarchy)
    debug_log(f"Span count: {span1['spanID']} has {span_count1}, {span2['spanID']} has {span_count2}")
    if span_count1 != span_count2:
        debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - total span count mismatch: {span_count1} vs {span_count2}")
        return False
    
    if depth == 0:
        time_diff = abs(span1["startTime"] - span2["startTime"])
        debug_log(f"Time diff: {time_diff}us")
        if time_diff > start_difference:
            debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - start time diff > {start_difference}us: {time_diff}us")
            return False
        end1 = span1["startTime"] + span1["duration"]
        end2 = span2["startTime"] + span2["duration"]
        if end1 < span2["startTime"]:
            gap = span2["startTime"] - end1
            debug_log(f"Gap check: {span1['spanID']} ends {end1}, {span2['spanID']} starts {span2['startTime']}, gap {gap}us")
            if gap_difference >= 0 and gap > gap_difference:
                debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - gap > {gap_difference}us: {gap}us")
                return False
        elif end2 < span1["startTime"]:
            gap = span1["startTime"] - end2
            debug_log(f"Gap check: {span2['spanID']} ends {end2}, {span1['spanID']} starts {span1['startTime']}, gap {gap}us")
            if gap_difference >= 0 and gap > gap_difference:
                debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - gap > {gap_difference}us: {gap}us")
                return False
        if gap_difference < 0:  # Strict overlap
            overlap = min(end1, end2) - max(span1["startTime"], span2["startTime"])
            min_overlap = -gap_difference
            debug_log(f"Overlap check: {span1['spanID']} vs {span2['spanID']}, overlap {overlap}us, min required {min_overlap}us")
            if overlap < min_overlap:
                debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - overlap < {min_overlap}us: {overlap}us")
                return False
        duration_diff = abs(span1["duration"] - span2["duration"])
        max_duration = max(span1["duration"], span2["duration"])
        debug_log(f"Duration diff: {duration_diff}us, max: {max_duration}us, 20% threshold: {0.2 * max_duration}us")
        if span1["duration"] < 20000 and span2["duration"] < 20000:
            if duration_diff > 100000:
                debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - short span duration diff > 100ms: {duration_diff}us")
                return False
            debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - short span duration diff OK: {duration_diff}us")
        elif span1["duration"] >= 20000 or span2["duration"] >= 20000:
            if duration_diff > 100000:
                debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - duration diff > 100ms: {duration_diff}us")
                return False
            if duration_diff > 0.2 * max_duration:
                debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - duration diff > 20% of max: {duration_diff}us vs {0.2 * max_duration}us")
                return False
            debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - duration diff OK: {duration_diff}us vs max {max_duration}us")
    
    if span1["operationName"] != span2["operationName"]:
        if not (is_db_span(span1) and is_db_span(span2) and span1["operationName"].startswith("QUERY") and span2["operationName"].startswith("QUERY")):
            debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - operationName mismatch: {span1['operationName']} vs {span2['operationName']}")
            return False
        debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - DB QUERY operations treated as equivalent")
    
    debug_log(f"Span {span1['spanID']} children: {[c['spanID'] + ' ' + c['operationName'] for c in children1]}")
    debug_log(f"Span {span2['spanID']} children: {[c['spanID'] + ' ' + c['operationName'] for c in children2]}")
    
    if not children1 and not children2:
        debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - leaf nodes match")
        return True
    
    if len(children1) != len(children2):
        debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - child count mismatch: {len(children1)} vs {len(children2)}")
        return False
    
    if any(is_db_span(c) for c in children1):
        query_count1 = sum(1 for c in children1 if is_db_span(c))
        query_count2 = sum(1 for c in children2 if is_db_span(c))
        debug_log(f"Query count: {span1['spanID']} has {query_count1}, {span2['spanID']} has {query_count2}")
        if query_count1 != query_count2:
            debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - DB query count mismatch: {query_count1} vs {query_count2}")
            return False
        debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - DB query counts match: {query_count1}")
    else:
        for c1, c2 in zip(children1, children2):
            if not compare_subtrees(c1, c2, span_dict, hierarchy, processes, depth + 1):
                debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - child comparison failed at depth {depth + 1}")
                return False
    
    debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - subtrees match fully")
    return True
    
def cluster_parallel_subtrees(spans, span_dict, hierarchy, processes, parent_id, depth):
    debug_log(f"Clustering spans for parent {parent_id} at depth {depth}: {[s['spanID'] + ' ' + s['operationName'] for s in spans]}")
    spans = sorted(spans, key=lambda x: x["startTime"])
    
    clusters = []
    remaining = spans[:]
    while remaining:
        root = remaining.pop(0)
        debug_log(f"Processing root span {root['spanID']} - {root['operationName']}")
        if is_db_span(root):
            debug_log(f"Skipping span {root['spanID']} - root is a DB query")
            continue
        cluster = [(root, count_total_spans(root, hierarchy))]
        i = 0
        while i < len(remaining):
            candidate = remaining[i]
            debug_log(f"Comparing root {root['spanID']} (start: {root['startTime']}, dur: {root['duration']}) vs candidate {candidate['spanID']} (start: {candidate['startTime']}, dur: {candidate['duration']})")
            if compare_subtrees(root, candidate, span_dict, hierarchy, processes, 0):
                cluster.append((remaining.pop(i), count_total_spans(candidate, hierarchy)))
                debug_log(f"Added {candidate['spanID']} to cluster with root {root['spanID']}")
            else:
                debug_log(f"No match between {root['spanID']} and {candidate['spanID']} - failed criteria")
                i += 1
        debug_log(f"Finished clustering attempt with root {root['spanID']}, cluster size: {len(cluster)}")
        if len(cluster) >= 2:
            clusters.append(cluster)
            debug_log(f"Cluster formed for parent {parent_id} at depth {depth}: {[s[0]['spanID'] for s in cluster]}")
        else:
            debug_log(f"Span {root['spanID']} not clustered - no matches found")
    
    debug_log(f"Clustering complete for parent {parent_id} at depth {depth} - {len(clusters)} clusters formed")
    return clusters

def find_duplicate_spans(file_path):
    try:
        with open(file_path, "r", encoding='utf-8') as file:
            parser = ijson.parse(file)
            spans = []
            processes = {}
            trace_id = None
            current_span = None
            current_span_tags = []
            current_references = []

            debug_log("Starting parsing with UTF-8")

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

    except UnicodeDecodeError:
        debug_log("UTF-8 decoding failed, falling back to Latin-1")
        with open(file_path, "r", encoding='latin-1') as file:
            parser = ijson.parse(file)
            spans = []
            processes = {}
            trace_id = None
            current_span = None
            current_span_tags = []
            current_references = []

            debug_log("Starting parsing with Latin-1")

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
    depth_map = {span_id: get_hierarchy_depth(span_dict, hierarchy, span_id) for span_id in span_dict}

    parent_groups = defaultdict(list)
    for span in span_dict.values():
        depth = depth_map[span["spanID"]]
        debug_log(f"Span {span['spanID']} has depth {depth}")
        if depth < 1:
            debug_log(f"Skipping span {span['spanID']} - depth {depth} < 1")
            continue
        parent_id = None
        for ref in span.get("references", []):
            if ref["refType"] == "CHILD_OF" and ref["spanID"] in span_dict:
                parent_id = ref["spanID"]
                break
        if parent_id:
            parent_groups[parent_id].append(span)
            debug_log(f"Span {span['spanID']} grouped under parent {parent_id}: {span['operationName']}")

    duplicate_groups = {}
    for parent_id, group in parent_groups.items():
        debug_log(f"Group for parent {parent_id}: {[s['spanID'] + ' ' + s['operationName'] for s in group]}")
        if len(group) > 1:
            debug_log(f"Processing group for parent {parent_id} with {len(group)} spans")
            clusters = cluster_parallel_subtrees(group, span_dict, hierarchy, processes, parent_id, 0)
            if clusters:
                duplicate_groups[parent_id] = clusters
            else:
                debug_log(f"No clusters formed for parent {parent_id}")
        else:
            debug_log(f"Skipping clustering for parent {parent_id} - no duplicates (size: {len(group)})")

    debug_log(f"Final processes dict: {processes}")
    debug_log(f"Depth map: {depth_map}")
    return duplicate_groups, trace_id, processes, span_dict, hierarchy

def summarize_duplicates(duplicate_groups, trace_id, processes, span_dict, hierarchy):
    lines = [f"\nRelated Subtrees in Trace ID: {trace_id}\n"]
    if not duplicate_groups:
        lines.append("No matching parallel subtrees found.")
        return "\n".join(lines), {}

    def get_leaf_operations_with_depth(span, hierarchy, current_depth=0):
        kids = hierarchy.get(span["spanID"], [])
        leaf_ops = []
        if not kids:
            tags = span.get("tags", {})
            pid = span.get("processID", "")
            service = processes.get(pid, {}).get("serviceName", "Unknown")
            db_sample = None
            op = span.get("operationName", "UNKNOWN")
            debug_log(f"Processing span {span['spanID']}, original op: {op}")
            if "db.statement" in tags:
                db_operation = tags.get("db.operation", None)
                raw_statement = tags.get("db.statement", "").strip().upper()
                if db_operation:
                    op = f"{service} DB QUERY {db_operation}"
                    if raw_statement:
                        if db_operation.upper() not in raw_statement.split()[0]:
                            debug_log(f"Span {span['spanID']} - db.operation '{db_operation}' does not match db.statement '{raw_statement}'")
                            db_sample = f"MISMATCH (Expected {db_operation})"
                        else:
                            db_sample = (raw_statement[:50] + "...") if len(raw_statement) > 50 else raw_statement
                    else:
                        db_sample = "NO STATEMENT"
                else:
                    # Smarter detection: Look for SQL keywords in the statement
                    stmt_words = raw_statement.split()
                    if "SELECT" in stmt_words:
                        op = f"{service} DB QUERY SELECT"
                    elif "INSERT" in stmt_words:
                        op = f"{service} DB QUERY INSERT"
                    elif "UPDATE" in stmt_words:
                        op = f"{service} DB QUERY UPDATE"
                    elif "DELETE" in stmt_words:
                        op = f"{service} DB QUERY DELETE"
                    else:
                        op = f"{service} DB QUERY"
                    db_sample = (raw_statement[:50] + "...") if len(raw_statement) > 50 else raw_statement or "NO STATEMENT"
            elif "http.method" in tags:
                op = f"{service} HTTP {tags['http.method']}"
            else:
                if "ack" in op.lower() and "-" in op:
                    op = f"{service} ack"
                else:
                    op = f"{service} {op}"
            debug_log(f"Leaf span {span['spanID']}: {op}, sample: {db_sample}")
            leaf_ops.append((op, current_depth, db_sample, span["spanID"]))
        for child in kids:
            leaf_ops.extend(get_leaf_operations_with_depth(child, hierarchy, current_depth + 1))
        return leaf_ops

    grouped_clusters = defaultdict(list)
    for parent_id, clusters in sorted(duplicate_groups.items()):
        for cluster in clusters:
            operation = cluster[0][0]["operationName"]
            grouped_clusters[(parent_id, operation)].append(cluster)

    cluster_leaf_ops = {}
    for (parent_id, operation), clusters in sorted(grouped_clusters.items()):
        span = span_dict.get(parent_id, {})
        parent_op = span.get("operationName", "Unknown")
        parent_service, _ = extract_service_names(span, processes, span_dict)
        if span.get("tags", {}).get("span.kind") == "server":
            parent_service = processes.get(span.get("processID", ""), {}).get("serviceName", "Unknown")
        
        lines.append(f"Parent: {parent_service} - {parent_op} (Span ID: {parent_id})")
        lines.append(f"Operation: {operation}")
        
        for cluster_idx, cluster in enumerate(clusters[:10]):
            req, rec = extract_service_names(cluster[0][0], processes, span_dict)
            depth = get_hierarchy_depth(span_dict, hierarchy, cluster[0][0]["spanID"])
            total_spans = sum(count for _, count in cluster)
            lines.append(f"- Requesting: {req}, Receiving: {rec} (Size: {len(cluster)}, Depth: {depth}, Spans: {total_spans}):")
            for j, (span, _) in enumerate(cluster[:5], 1):
                start_time = parse_time(span["startTime"])
                duration = span["duration"]
                status_code = extract_status_code(span["tags"])
                lines.append(f"  Subtree Root {j} - ID: {span['spanID']}, Start: {start_time}, Duration: {duration}us, Status: {status_code}")
            if len(cluster) > 5:
                lines.append(f"    ...and {len(cluster) - 5} more subtrees")
            
            leaf_ops_with_depth = get_leaf_operations_with_depth(cluster[0][0], hierarchy)
            total_leaves = len(leaf_ops_with_depth)
            debug_log(f"Cluster {operation} under parent {parent_id}: Total leaves = {total_leaves}")
            depth_ops = defaultdict(list)
            for op, d, sample, span_id in leaf_ops_with_depth:
                depth_ops[d].append((op, sample, span_id))
            lines.append(f"  Leaf Operations by Depth: Total {total_leaves}")
            for d in sorted(depth_ops.keys()):
                op_counts = Counter(op for op, _, _ in depth_ops[d])
                lines.append(f"    Depth {d}:")
                for op, count in op_counts.items():
                    sample = next(s for o, s, _ in depth_ops[d] if o == op)
                    if "DB QUERY" in op and sample:
                        lines.append(f"      {count:<2} {op} (e.g., {sample})")
                    else:
                        lines.append(f"      {count:<2} {op}")
            lines.append("")

            cluster_key = f"{parent_id}:{operation}"
            all_leaf_ops = []
            for subtree_idx, (root_span, _) in enumerate(cluster):
                subtree_leaves = get_leaf_operations_with_depth(root_span, hierarchy)
                all_leaf_ops.extend(subtree_leaves)
                debug_log(f"Collected {len(subtree_leaves)} leaf ops from subtree {subtree_idx} in cluster {cluster_key}")

            depth_ops_all = defaultdict(list)
            for op, d, sample, span_id in all_leaf_ops:
                depth_ops_all[d].append((op, sample, span_id))
            cluster_leaf_ops[cluster_key] = {
                "total_leaves": total_leaves,
                "by_depth": {
                    str(d): [{"operation": op, "count": count, "sample": next(s for o, s, _ in depth_ops_all[d] if o == op), "span_ids": [sid for o, _, sid in depth_ops_all[d] if o == op]}
                             for op, count in Counter(op for op, _, _ in depth_ops_all[d]).items()]
                    for d in sorted(depth_ops_all.keys())
                }
            }
        lines.append("-" * 40)

    return "\n".join(lines), cluster_leaf_ops

def get_subtree_spans(root_span, hierarchy, span_dict):
    """Collect all spans in the subtree rooted at root_span, preserving hierarchy."""
    spans = [root_span]
    children = hierarchy.get(root_span["spanID"], [])
    for child in children:
        spans.extend(get_subtree_spans(child, hierarchy, span_dict))
    return spans

def convert_tags_to_jaeger_format(tags_dict):
    """Convert a dictionary of tags to Jaeger's expected list of tag objects."""
    tag_list = []
    for key, value in tags_dict.items():
        tag_type = "string"
        if isinstance(value, int):
            tag_type = "int64"
        elif isinstance(value, float):
            tag_type = "float64"
        elif isinstance(value, bool):
            tag_type = "bool"
        tag_list.append({
            "key": key,
            "type": tag_type,
            "value": value
        })
    return tag_list

def export_clustered_traces_json(duplicate_groups, trace_id, processes, span_dict, hierarchy, cluster_leaf_ops, output_file="clustered_traces.json"):
    """Export each cluster of matching subtrees as a single trace in Jaeger-compatible JSON format, preserving original spanIDs and parent operation."""
    if not duplicate_groups:
        debug_log("No duplicate groups found to export.")
        return

    output_data = []
    grouped_clusters = defaultdict(list)
    for parent_id, clusters in duplicate_groups.items():
        for cluster in clusters:
            operation = cluster[0][0]["operationName"]
            grouped_clusters[(parent_id, operation)].append(cluster)

    for (parent_id, operation), clusters in sorted(grouped_clusters.items()):
        cluster_key = f"{parent_id}:{operation}"
        leaf_ops_data = cluster_leaf_ops.get(cluster_key, {})
        span_op_map = {}
        for depth, ops in leaf_ops_data.get("by_depth", {}).items():
            for op_data in ops:
                operation_name = op_data["operation"]
                sample = op_data["sample"]
                for span_id in op_data["span_ids"]:
                    span_op_map[span_id] = {"operation": operation_name, "sample": sample}

        for cluster_idx, cluster in enumerate(clusters):
            total_subtree_spans = sum(count for _, count in cluster)
            cluster_size = len(cluster)
            spans_per_subtree = total_subtree_spans // cluster_size
            debug_log(f"Cluster {cluster_idx + 1} under parent {parent_id}, operation {operation} has size: {cluster_size}, total subtree spans: {total_subtree_spans}, spans per subtree: {spans_per_subtree}")

            new_trace_id = str(uuid.uuid4()).replace("-", "")
            parent_span = span_dict.get(parent_id)
            if not parent_span:
                debug_log(f"Warning: Parent span {parent_id} not found in span_dict for cluster {cluster_idx + 1}")
                continue

            first_subtree_root = cluster[0][0]
            requesting_service = processes.get(first_subtree_root.get("processID", ""), {}).get("serviceName", "Unknown")
            subtree_operation = first_subtree_root["operationName"]

            all_spans = [parent_span]
            involved_processes = set([parent_span.get("processID")]) if parent_span.get("processID") else set()
            seen_span_ids = {parent_span["spanID"]}

            for subtree_idx, (root_span, _) in enumerate(cluster):
                subtree_spans = get_subtree_spans(root_span, hierarchy, span_dict)
                debug_log(f"Subtree {subtree_idx + 1} in cluster {cluster_idx + 1} has {len(subtree_spans)} spans")
                for span in subtree_spans:
                    if span["spanID"] not in seen_span_ids:
                        all_spans.append(span)
                        seen_span_ids.add(span["spanID"])

            new_spans = []
            total_spans_excluding_parent = len(all_spans) - 1
            total_spans_in_trace = len(all_spans)
            debug_log(f"Total spans in trace (including parent): {total_spans_in_trace}, reported spans (excluding parent): {total_spans_excluding_parent}")

            for span_idx, span in enumerate(all_spans):
                new_span = span.copy()
                new_span["traceID"] = new_trace_id
                new_span["spanID"] = span["spanID"]

                if span["spanID"] in span_op_map:
                    original_op = new_span["operationName"]
                    new_span["operationName"] = span_op_map[span["spanID"]]["operation"]
                    debug_log(f"Updated span {span['spanID']} from {original_op} to {new_span['operationName']}")

                new_references = []
                for ref in new_span.get("references", []):
                    new_ref = ref.copy()
                    new_ref["traceID"] = new_trace_id
                    new_ref["spanID"] = ref["spanID"]
                    new_references.append(new_ref)
                new_span["references"] = new_references

                if "tags" in new_span:
                    new_span["tags"] = convert_tags_to_jaeger_format(new_span["tags"])
                else:
                    new_span["tags"] = []

                if "logs" not in new_span:
                    new_span["logs"] = []
                if "warnings" not in new_span:
                    new_span["warnings"] = None

                if span_idx == 0:  # Parent span
                    original_operation = new_span["operationName"]  # Keep as is
                    new_span["tags"].extend([
                        {"key": "original.operationName", "type": "string", "value": original_operation},
                        {"key": "clustered.operationName", "type": "string", "value": subtree_operation},  # Add subtree operation as a tag
                        {"key": "cluster.group", "type": "string", "value": f"{parent_id}:{operation}"},
                        {"key": "cluster.size", "type": "int64", "value": cluster_size},
                        {"key": "cluster.total_subtree_spans", "type": "int64", "value": total_subtree_spans},
                        {"key": "spans.per.subtree", "type": "int64", "value": spans_per_subtree},
                        {"key": "reported.spans.in.trace", "type": "int64", "value": total_spans_excluding_parent},
                        {"key": "actual.spans.in.trace", "type": "int64", "value": total_spans_in_trace}
                    ])
                else:
                    subtree_idx = (span_idx - 1) // spans_per_subtree
                    new_span["tags"].append({"key": "subtree.index", "type": "int64", "value": subtree_idx})
                    new_span["tags"].append({"key": "cluster.group", "type": "string", "value": f"{parent_id}:{operation}"})
                    if span["spanID"] in span_op_map and span_op_map[span["spanID"]]["sample"]:
                        new_span["tags"].append({
                            "key": "db.statement.sample",
                            "type": "string",
                            "value": span_op_map[span["spanID"]]["sample"]
                        })

                if "processID" in new_span:
                    involved_processes.add(new_span["processID"])

                new_spans.append(new_span)

            trace_processes = {pid: processes[pid] for pid in involved_processes if pid in processes}
            output_data.append({
                "traceID": new_trace_id,
                "spans": new_spans,
                "processes": trace_processes
            })
            debug_log(f"Exported trace {new_trace_id} for cluster {cluster_idx + 1} under parent {parent_id}, operation {operation}, total spans in this trace: {len(new_spans)}, reported spans: {total_spans_excluding_parent}")

    output_json = {"data": output_data}
    try:
        with open(output_file, "w", encoding='utf-8') as f:
            json.dump(output_json, f, indent=4)
        debug_log(f"Successfully wrote {len(output_data)} clustered traces to {output_file}")
        print(f"Clustered traces exported to {output_file} with {len(output_data)} traces")
        print("Note: Each trace includes the parent span and all matching subtrees. The 'reported.spans.in.trace' tag excludes the parent to match log.txt, while Jaeger UI shows all spans including the parent.")
    except Exception as e:
        debug_log(f"Error writing JSON output: {str(e)}")
        print(f"Error writing JSON output: {e}", file=sys.stderr)
        
if __name__ == "__main__":
    try:
        duplicate_groups, trace_id, processes, span_dict, hierarchy = find_duplicate_spans(trace_file)
        log_output, cluster_leaf_ops = summarize_duplicates(duplicate_groups, trace_id, processes, span_dict, hierarchy)
        print(log_output)
        # Add the export of clustered traces with leaf operations
        export_clustered_traces_json(duplicate_groups, trace_id, processes, span_dict, hierarchy, cluster_leaf_ops)
    except Exception as e:
        debug_log(f"Error: {str(e)}")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        debug_file.close()
