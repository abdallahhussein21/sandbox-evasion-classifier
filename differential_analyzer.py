import json, sys, os

def load_report(task_id):
    path = "/home/abdallah/CAPEv2/storage/analyses/" + str(task_id) + "/reports/report.json"
    if not os.path.exists(path):
        print("Report not found for task " + str(task_id))
        return None
    with open(path) as f:
        return json.load(f)

def extract_api_calls(report):
    calls = []
    try:
        for process in report["behavior"]["processes"]:
            for call in process["calls"]:
                calls.append(call["api"])
    except: pass
    return calls

def extract_signatures(report):
    sigs = []
    try:
        for sig in report["signatures"]:
            sigs.append(sig["name"])
    except: pass
    return sigs

def compare_reports(task1, task2):
    r1 = load_report(task1)
    r2 = load_report(task2)
    if not r1 or not r2: return
    apis1 = set(extract_api_calls(r1))
    apis2 = set(extract_api_calls(r2))
    sigs1 = set(extract_signatures(r1))
    sigs2 = set(extract_signatures(r2))
    print("=== Differential Analysis: Task " + str(task1) + " vs Task " + str(task2) + " ===")
    print("API calls only in Task " + str(task1) + ": " + str(apis1 - apis2))
    print("API calls only in Task " + str(task2) + ": " + str(apis2 - apis1))
    print("Common API calls: " + str(apis1 & apis2))
    print("Signatures in Task " + str(task1) + ": " + str(sigs1))
    print("Signatures in Task " + str(task2) + ": " + str(sigs2))
    if sigs1 != sigs2 or apis1 != apis2:
        print("Evasion detected: YES")
    else:
        print("Evasion detected: NO")

compare_reports(sys.argv[1], sys.argv[2])
