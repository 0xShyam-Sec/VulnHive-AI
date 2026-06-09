"""Minimal Flask app with deliberately planted issues for integration tests."""

from flask import Flask, request, make_response

app = Flask(__name__)


@app.route("/")
def index():
    resp = make_response("<h1>Mock target</h1>", 200)
    resp.headers["Server"] = "MockApp/1.0"
    resp.headers["X-Powered-By"] = "Python/3.9"
    return resp


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<html><body>You searched for: {q}</body></html>", 200


@app.route("/api/user")
def api_user():
    uid = request.args.get("id", "1")
    return {"id": uid, "name": f"user{uid}", "email": f"u{uid}@x.test"}, 200


@app.route("/.env")
def dot_env():
    return "API_KEY=secret123\nDB=postgres://", 200, {"Content-Type": "text/plain"}


def run(port: int = 8765):
    app.run(host="127.0.0.1", port=port, use_reloader=False)


if __name__ == "__main__":
    run()
