def generate_html_report(scan_id: int, results: dict):
    html = f"""
    <html>
    <head><title>Scan Report #{scan_id}</title></head>
    <body>
        <h1>SamSec – Scan Report #{scan_id}</h1>

        <h2>Subfinder Results</h2>
        <pre>{results["subfinder"]}</pre>

        <h2>Nuclei Results</h2>
        <pre>{results["nuclei"]}</pre>
    </body>
    </html>
    """

    path = f"/tmp/samsec/report_{scan_id}.html"
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    return path
