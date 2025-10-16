import json
from textwrap import dedent

INPUT_FILE = "/home/kali/chainsaw_output/detections.json"
OUTPUT_FILE = "chainsaw_report.md"
CHUNK_SIZE = 15  # Split batches (you can change to 10 if needed)


def load_detections():
    with open(INPUT_FILE, "r") as f:
        return json.load(f)


def chunk_detections(detections, size):
    for i in range(0, len(detections), size):
        yield detections[i : i + size]


def summarize_detection(detection):
    title = detection.get("name", "Untitled")
    severity = detection.get("level", "unknown").capitalize()
    rule_id = detection.get("id", "N/A")
    logsource = detection.get("logsource", {})
    timestamp = detection.get("timestamp", "N/A")
    category = logsource.get("category", "N/A")
    product = logsource.get("product", "N/A")
    authors = detection.get("authors", [])
    tags = detection.get("tags", [])
    references = detection.get("references", [])
    falsepositives = detection.get("falsepositives", [])

    markdown = f"""
    ### 🛡️ {title}
    **Severity:** {severity}
    **Timestamp:** `{timestamp}`
    **Rule ID:** `{rule_id}`
    **Product:** `{product}`
    **Category:** `{category}`
    **Authors:** {", ".join(authors) if authors else "Unknown"}

    **Tactics/Techniques:**
    {" • ".join(tags) if tags else "None"}

    **False Positives:**
    {" - " + "\n - ".join(falsepositives) if falsepositives else "None listed."}

    **References:**
    {" - " + "\n - ".join(references) if references else "None listed."}

    ---
    """
    return dedent(markdown.strip()) + "\n\n"


def write_report(detections, output_path):
    with open(output_path, "w") as out_file:
        out_file.write("# 🔍 Chainsaw Detection Summary\n\n")
        out_file.write("This report contains Sigma rule detections from Chainsaw on parsed Windows event logs.\n\n")

        for block in chunk_detections(detections, CHUNK_SIZE):
            for det in block:
                summary = summarize_detection(det)
                out_file.write(summary)

        print(f"[+] Markdown report written to: {output_path}")


if __name__ == "__main__":
    detections = load_detections()
    write_report(detections, OUTPUT_FILE)
