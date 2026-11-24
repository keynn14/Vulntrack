import hmac
import os
from contextlib import contextmanager
from flask import Flask, Response, jsonify, request
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeTransform
from lxml import etree

app = Flask(__name__)

# Standard Greenbone XML report format UUID
XML_REPORT_FORMAT_ID = "a994b278-1f62-11e1-96ac-406186ea4fc5"


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _check_api_key():
    expected = os.environ.get("BRIDGE_API_KEY", "")
    provided = request.headers.get("X-Api-Key", "")
    if not expected or not hmac.compare_digest(provided, expected):
        return jsonify(error="Unauthorized"), 401
    return None


@contextmanager
def _gmp_session():
    conn = UnixSocketConnection(path=_require_env("GVMD_SOCKET"))
    with GMP(connection=conn, transform=EtreeTransform()) as gmp:
        gmp.authenticate(_require_env("GMP_USER"), _require_env("GMP_PASSWORD"))
        yield gmp


@app.get("/health")
def health():
    if (err := _check_api_key()) is not None:
        return err
    try:
        with _gmp_session() as gmp:
            ver = gmp.get_version()
            return jsonify(status="ok", gmp_version=ver.findtext("version") or "unknown")
    except Exception as exc:
        return jsonify(status="error", error=str(exc)), 503


@app.post("/scans")
def start_scan():
    if (err := _check_api_key()) is not None:
        return err

    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    hosts = body.get("hosts") or []
    if not name or not isinstance(hosts, list) or len(hosts) == 0:
        return jsonify(error="Request body must include non-empty 'name' and 'hosts' list."), 400

    with _gmp_session() as gmp:
        target = gmp.create_target(
            name=name,
            hosts=hosts,
            port_list_id=_require_env("PORT_LIST_ID"),
        )
        target_id = target.get("id")

        task = gmp.create_task(
            name=name,
            config_id=_require_env("SCAN_CONFIG_ID"),
            target_id=target_id,
            scanner_id=_require_env("SCANNER_ID"),
        )
        task_id = task.get("id")

        started = gmp.start_task(task_id)
        report_id = started.findtext("report_id")
        return jsonify(task_id=task_id, report_id=report_id), 201


@app.get("/scans/<task_id>")
def scan_status(task_id: str):
    if (err := _check_api_key()) is not None:
        return err

    with _gmp_session() as gmp:
        task = gmp.get_task(task_id)
        status = task.findtext(".//status") or "Unknown"
        progress = task.findtext(".//progress") or "0"
        return jsonify(task_id=task_id, status=status, progress=progress)


@app.get("/reports/<report_id>")
def get_report(report_id: str):
    if (err := _check_api_key()) is not None:
        return err

    with _gmp_session() as gmp:
        report = gmp.get_report(
            report_id=report_id,
            report_format_id=XML_REPORT_FORMAT_ID,
            ignore_pagination=True,
        )
        xml_bytes = etree.tostring(report, xml_declaration=True, encoding="utf-8")
        return Response(xml_bytes, mimetype="application/xml")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8085")))
