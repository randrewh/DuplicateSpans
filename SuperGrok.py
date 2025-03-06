# -*- coding: utf-8 -*-
import ijson
from collections import defaultdict, Counter
from datetime import datetime
import sys
from urllib.parse import urlparse

sys.stdout.reconfigure(encoding='utf-8')

if len(sys.argv) < 2:
    print("Usage: python SuperGrok.py <path_to_trace_file>")
    sys.exit(1)

trace_file = sys.argv[1]

debug_file = open("debug_log.txt", "w", encoding='utf-8')

def debug_log(message):
    print(f"[DEBUG] {message}", file=debug_file)

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
                debug_log(f"Defaulting path to /* for span {span['spanID']} with method {method}")
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
            debug_log(f"DB span {span['spanID']} operationName set to: {operation_name}")
        
        else:
            debug_log(f"Skipping non-HTTP/DB span {span['spanID']}")
            continue
        
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
    else:  # client
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

def get_last_generation_operation(span, hierarchy, processes):
    children = hierarchy.get(span["spanID"], [])
    if not children:
        tags = span.get("tags", {})
        pid = span.get("processID", "")
        service_name = processes.get(pid, {}).get("serviceName", "Unknown")
        if "db.statement" in tags:
            db_statement = tags["db.statement"]
            db_table = tags.get("db.sql.table", "unknown_table")
            if db_table == "unknown_table" and db_statement:
                parts = db_statement.upper().split("FROM")
                if len(parts) > 1:
                    after_from = parts[1].strip().split()[0].lower()
                    if after_from not in ("select", "insert", "update", "delete", "where", "join", "as"):
                        db_table = after_from
            db_system = tags.get("db.system", "")
            prefix = f"{db_system} " if db_system else ""
            verb = db_statement.split()[0].upper() if db_statement else "QUERY"
            op = f"{prefix}QUERY {verb} {db_table}"
        else:
            op = span["operationName"]
        full_op = op if len(op) <= 50 else f"{op[:47]}..."
        return full_op, service_name
    
    leaf_ops = []
    for child in children:
        leaf_op, leaf_service = get_last_generation_operation(child, hierarchy, processes)
        leaf_ops.append((leaf_op, leaf_service))
    
    if len(leaf_ops) > 1:
        op, service = leaf_ops[0]
        return f"{op} (+{len(leaf_ops)-1} more)", service
    return leaf_ops[0]

def compare_subtrees(span1, span2, span_dict, hierarchy, processes, depth):
    debug_log(f"Comparing spans {span1['spanID']} vs {span2['spanID']} at depth {depth}")
    children1 = sorted(hierarchy.get(span1["spanID"], []), key=lambda x: x["operationName"])
    children2 = sorted(hierarchy.get(span2["spanID"], []), key=lambda x: x["operationName"])
    
    def get_max_depth(span_id, current_depth=0):
        kids = hierarchy.get(span_id, [])
        if not kids:
            return current_depth
        return max(get_max_depth(k["spanID"], current_depth + 1) for k in kids)
    
    depth1 = get_max_depth(span1["spanID"])
    depth2 = get_max_depth(span2["spanID"])
    if depth1 < 2 or depth2 < 2 or depth1 != depth2:
        debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - depth mismatch or < 2: {depth1} vs {depth2}")
        return False
    
    if depth == 0:
        time_diff = abs(span1["startTime"] - span2["startTime"])
        if time_diff > 500_000:
            debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - start time diff > 500ms: {time_diff}us")
            return False
        end1 = span1["startTime"] + span1["duration"]
        end2 = span2["startTime"] + span2["duration"]
        if end1 < span2["startTime"]:
            gap = span2["startTime"] - end1
            if gap > 150_000:
                debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - gap > 150ms: {gap}us")
                return False
        elif end2 < span1["startTime"]:
            gap = span1["startTime"] - end2
            if gap > 150_000:
                debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - gap > 150ms: {gap}us")
                return False
        duration_diff = abs(span1["duration"] - span2["duration"])
        max_duration = max(span1["duration"], span2["duration"])
        if duration_diff > 100_000 and duration_diff > 0.2 * max_duration:
            debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - duration diff exceeds both 100ms and 20%: {duration_diff}us vs max {max_duration}us")
            return False
        else:
            debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - duration diff OK: {duration_diff}us vs max {max_duration}us")
    
    if span1["operationName"] != span2["operationName"]:
        if not (is_db_span(span1) and is_db_span(span2) and span1["operationName"].startswith("QUERY") and span2["operationName"].startswith("QUERY")):
            debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - operationName mismatch: {span1['operationName']} vs {span2['operationName']}")
            return False
        else:
            debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - DB QUERY operations treated as equivalent")
    
    if not children1 and not children2:
        debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - leaf nodes match")
        return True
    
    if len(children1) != len(children2):
        debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - child count mismatch: {len(children1)} vs {len(children2)}")
        return False
    
    if any(is_db_span(c) for c in children1):
        query_count1 = sum(1 for c in children1 if is_db_span(c))
        query_count2 = sum(1 for c in children2 if is_db_span(c))
        if abs(query_count1 - query_count2) > 1:
            debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - DB query count mismatch: {query_count1} vs {query_count2}")
            return False
        debug_log(f"Span {span1['spanID']} vs {span2['spanID']} - DB query counts close enough: {query_count1} vs {query_count2}")
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
        if is_db_span(root):
            debug_log(f"Skipping span {root['spanID']} - root is a DB query")
            continue
        cluster = [root]
        i = 0
        while i < len(remaining):
            candidate = remaining[i]
            debug_log(f"Attempting to match root {root['spanID']} with candidate {candidate['spanID']}")
            if compare_subtrees(root, candidate, span_dict, hierarchy, processes, 0):
                cluster.append(remaining.pop(i))
                debug_log(f"Added {candidate['spanID']} to cluster with root {root['spanID']}")
            else:
                i += 1
        debug_log(f"Finished clustering attempt with root {root['spanID']}, cluster size: {len(cluster)}")
        if len(cluster) >= 2:
            clusters.append(cluster)
            debug_log(f"Cluster formed for parent {parent_id} at depth {depth}: {[s['spanID'] for s in cluster]}")
        else:
            debug_log(f"Span {root['spanID']} not clustered - no matches found")
    
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

    parent_depth_groups = defaultdict(list)
    for span in span_dict.values():
        depth = depth_map[span["spanID"]]
        debug_log(f"Span {span['spanID']} has depth {depth}")
        if depth < 2:
            debug_log(f"Skipping span {span['spanID']} - depth {depth} < 2")
            continue
        parent_id = None
        for ref in span.get("references", []):
            if ref["refType"] == "CHILD_OF" and ref["spanID"] in span_dict:
                parent_id = ref["spanID"]
                break
        if parent_id:
            parent_depth_groups[(parent_id, depth)].append(span)
            debug_log(f"Span {span['spanID']} grouped under parent {parent_id} at depth {depth}: {span['operationName']}")

    duplicate_groups = {}
    for (parent_id, depth), group in parent_depth_groups.items():
        if len(group) > 1:
            debug_log(f"Processing group for parent {parent_id} at depth {depth} with {len(group)} spans")
            clusters = cluster_parallel_subtrees(group, span_dict, hierarchy, processes, parent_id, depth)
            if clusters:
                duplicate_groups[(parent_id, depth)] = clusters
            else:
                debug_log(f"No clusters formed for parent {parent_id} at depth {depth}")

    debug_log(f"Final processes dict: {processes}")
    debug_log(f"Depth map: {depth_map}")
    return duplicate_groups, trace_id, processes, span_dict, hierarchy

def summarize_duplicates(duplicate_groups, trace_id, processes, span_dict, hierarchy):
    lines = [f"\nParallel Matching Subtrees in Trace ID: {trace_id}\n"]
    if not duplicate_groups:
        lines.append("No matching parallel subtrees found.")
        return "\n".join(lines)

    for (parent_id, depth), clusters in sorted(duplicate_groups.items()):
        span = span_dict.get(parent_id, {})
        parent_op = span.get("operationName", "Unknown")
        parent_service, _ = extract_service_names(span, processes, span_dict)
        if span.get("tags", {}).get("span.kind") == "server":
            parent_service = processes.get(span.get("processID", ""), {}).get("serviceName", "Unknown")
        
        lines.append(f"Parent: {parent_service} - {parent_op} (Span ID: {parent_id}, Hierarchy Depth: {depth})")
        lines.append(f"Matching Subtree Count: {len(clusters)}\n")
        for i, cluster in enumerate(clusters[:10], 1):
            req, rec = extract_service_names(cluster[0], processes, span_dict)
            request = cluster[0]["operationName"]
            lines.append(f"Cluster {i} -- Requesting: {req}, Receiving: {rec}, Request: {request} (Size: {len(cluster)}):")
            for j, span in enumerate(cluster[:5], 1):
                start_time = parse_time(span["startTime"])
                duration = span["duration"]
                status_code = extract_status_code(span["tags"])
                lines.extend([
                    f"  Subtree Root {j} - ID: {span['spanID']}, Start: {start_time}, Duration: {duration}us, Status: {status_code}"
                ])
            if len(cluster) > 5:
                lines.append(f"    ...and {len(cluster) - 5} more subtrees")
            last_gen_op, last_gen_service = get_last_generation_operation(cluster[0], hierarchy, processes)
            lines.append(f"  Last Generation: {last_gen_service} {last_gen_op}")
            lines.append("")
        lines.append("-" * 40)

    return "\n".join(lines)

if __name__ == "__main__":
    try:
        duplicate_groups, trace_id, processes, span_dict, hierarchy = find_duplicate_spans(trace_file)
        print(summarize_duplicates(duplicate_groups, trace_id, processes, span_dict, hierarchy))
    except Exception as e:
        debug_log(f"Error: {str(e)}")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        debug_file.close()
