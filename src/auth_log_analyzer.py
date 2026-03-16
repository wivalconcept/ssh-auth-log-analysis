import re
import json
import argparse
import pandas as pd


def parse_auth_failures(log_file: str) -> pd.DataFrame:
    pattern = re.compile(
        r'(?P<month>\w+)\s+'
        r'(?P<day>\d+)\s+'
        r'(?P<time>\d+:\d+:\d+)\s+'
        r'(?P<host>\S+)\s+'
        r'sshd\(pam_unix\)\[\d+\]:\s+'
        r'authentication failure;.*?'
        r'rhost=(?P<rhost>\S+)'
        r'(?:\s+user=(?P<user>\S+))?'
    )

    records = []

    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                row = match.groupdict()
                if row["user"] is None:
                    row["user"] = "unknown"
                records.append(row)

    df = pd.DataFrame(records)

    if not df.empty:
        df["timestamp"] = pd.to_datetime(
            "2025 " + df["month"] + " " + df["day"] + " " + df["time"],
            format="%Y %b %d %H:%M:%S",
            errors="coerce"
        )

    return df


def build_report_data(df: pd.DataFrame, suspicious_threshold: int = 3) -> dict:
    if df.empty:
        return {
            "summary": {
                "total_authentication_failures": 0,
                "unique_remote_hosts": 0,
                "unique_targeted_users": 0,
                "suspicious_hosts_count": 0,
                "time_range": None
            },
            "top_remote_hosts": [],
            "top_targeted_users": [],
            "suspicious_hosts": [],
            "sample_events": [],
            "analyst_notes": [
                "No authentication failure entries were parsed."
            ]
        }

    failures_by_host = df["rhost"].value_counts().reset_index()
    failures_by_host.columns = ["rhost", "failed_attempts"]

    failures_by_user = df["user"].value_counts().reset_index()
    failures_by_user.columns = ["user", "failed_attempts"]

    suspicious_hosts = failures_by_host[
        failures_by_host["failed_attempts"] >= suspicious_threshold
    ]

    start_time = df["timestamp"].min()
    end_time = df["timestamp"].max()

    analyst_notes = []
    if suspicious_hosts.empty:
        analyst_notes.append(
            f"No host met the suspicious threshold of {suspicious_threshold} or more failures."
        )
        analyst_notes.append(
            "This may indicate low-volume activity, distributed attempts, or a small sample size."
        )
    else:
        top_host = failures_by_host.iloc[0]
        analyst_notes.append(
            f"The most active remote host was {top_host['rhost']} with {int(top_host['failed_attempts'])} failed attempts."
        )
        analyst_notes.append(
            "Repeated authentication failures from the same remote host may indicate brute-force or unauthorized access attempts."
        )

    return {
        "summary": {
            "total_authentication_failures": int(len(df)),
            "unique_remote_hosts": int(df["rhost"].nunique()),
            "unique_targeted_users": int(df["user"].nunique()),
            "suspicious_hosts_count": int(len(suspicious_hosts)),
            "time_range": {
                "start": str(start_time) if pd.notna(start_time) else None,
                "end": str(end_time) if pd.notna(end_time) else None,
            },
        },
        "top_remote_hosts": failures_by_host.head(10).to_dict(orient="records"),
        "top_targeted_users": failures_by_user.head(10).to_dict(orient="records"),
        "suspicious_hosts": suspicious_hosts.to_dict(orient="records"),
        "sample_events": df[["timestamp", "rhost", "user"]]
        .head(10)
        .assign(timestamp=lambda x: x["timestamp"].astype(str))
        .to_dict(orient="records"),
        "analyst_notes": analyst_notes,
    }


def save_txt_report(report_data: dict, output_file: str) -> None:
    with open(output_file, "w", encoding="utf-8") as report:
        report.write("SSH Authentication Failure Report\n")
        report.write("=" * 60 + "\n\n")

        summary = report_data["summary"]
        report.write("1. Executive Summary\n")
        report.write("-" * 60 + "\n")
        report.write(f"Total authentication failures: {summary['total_authentication_failures']}\n")
        report.write(f"Unique remote hosts: {summary['unique_remote_hosts']}\n")
        report.write(f"Unique targeted users: {summary['unique_targeted_users']}\n")
        report.write(f"Suspicious hosts count: {summary['suspicious_hosts_count']}\n")

        if summary["time_range"]:
            report.write(
                f"Time range: {summary['time_range']['start']} to {summary['time_range']['end']}\n"
            )
        else:
            report.write("Time range: N/A\n")

        report.write("\n2. Top Remote Hosts\n")
        report.write("-" * 60 + "\n")
        if report_data["top_remote_hosts"]:
            report.write(pd.DataFrame(report_data["top_remote_hosts"]).to_string(index=False))
        else:
            report.write("No data available.")
        report.write("\n\n")

        report.write("3. Top Targeted Users\n")
        report.write("-" * 60 + "\n")
        if report_data["top_targeted_users"]:
            report.write(pd.DataFrame(report_data["top_targeted_users"]).to_string(index=False))
        else:
            report.write("No data available.")
        report.write("\n\n")

        report.write("4. Suspicious Hosts\n")
        report.write("-" * 60 + "\n")
        if report_data["suspicious_hosts"]:
            report.write(pd.DataFrame(report_data["suspicious_hosts"]).to_string(index=False))
        else:
            report.write("No suspicious hosts detected.")
        report.write("\n\n")

        report.write("5. Sample Parsed Events\n")
        report.write("-" * 60 + "\n")
        if report_data["sample_events"]:
            report.write(pd.DataFrame(report_data["sample_events"]).to_string(index=False))
        else:
            report.write("No sample events available.")
        report.write("\n\n")

        report.write("6. Analyst Notes\n")
        report.write("-" * 60 + "\n")
        for note in report_data["analyst_notes"]:
            report.write(f"- {note}\n")


def save_csv_report(report_data: dict, output_file: str) -> None:
    rows = []

    summary = report_data["summary"]
    rows.append({
        "section": "summary",
        "key": "total_authentication_failures",
        "value": summary["total_authentication_failures"]
    })
    rows.append({
        "section": "summary",
        "key": "unique_remote_hosts",
        "value": summary["unique_remote_hosts"]
    })
    rows.append({
        "section": "summary",
        "key": "unique_targeted_users",
        "value": summary["unique_targeted_users"]
    })
    rows.append({
        "section": "summary",
        "key": "suspicious_hosts_count",
        "value": summary["suspicious_hosts_count"]
    })

    if summary["time_range"]:
        rows.append({
            "section": "summary",
            "key": "time_range_start",
            "value": summary["time_range"]["start"]
        })
        rows.append({
            "section": "summary",
            "key": "time_range_end",
            "value": summary["time_range"]["end"]
        })

    for row in report_data["top_remote_hosts"]:
        rows.append({
            "section": "top_remote_hosts",
            "key": row["rhost"],
            "value": row["failed_attempts"]
        })

    for row in report_data["top_targeted_users"]:
        rows.append({
            "section": "top_targeted_users",
            "key": row["user"],
            "value": row["failed_attempts"]
        })

    for row in report_data["suspicious_hosts"]:
        rows.append({
            "section": "suspicious_hosts",
            "key": row["rhost"],
            "value": row["failed_attempts"]
        })

    for row in report_data["sample_events"]:
        rows.append({
            "section": "sample_events",
            "key": f"{row['timestamp']} | {row['rhost']}",
            "value": row["user"]
        })

    for note in report_data["analyst_notes"]:
        rows.append({
            "section": "analyst_notes",
            "key": "note",
            "value": note
        })

    pd.DataFrame(rows).to_csv(output_file, index=False)


def save_json_report(report_data: dict, output_file: str) -> None:
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)


def main():
    parser = argparse.ArgumentParser(
        description="Parse SSH authentication failure logs and generate a report."
    )
    parser.add_argument(
        "-i", "--input",
        required=True,
        help="Path to the input log file"
    )
    parser.add_argument(
        "-o", "--output",
        required=True,
        help="Path to the output report file"
    )
    parser.add_argument(
        "-f", "--format",
        required=True,
        choices=["txt", "csv", "json"],
        help="Output report format"
    )
    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=3,
        help="Threshold for suspicious hosts (default: 3)"
    )

    args = parser.parse_args()

    df = parse_auth_failures(args.input)
    report_data = build_report_data(df, suspicious_threshold=args.threshold)

    if args.format == "txt":
        save_txt_report(report_data, args.output)
    elif args.format == "csv":
        save_csv_report(report_data, args.output)
    elif args.format == "json":
        save_json_report(report_data, args.output)

    print(f"Report generated successfully: {args.output}")
    print(f"Format: {args.format}")
    print(f"Suspicious threshold: {args.threshold}")


if __name__ == "__main__":
    main()

