"""Module: Awareness pages (what phishing is, how to spot it) and About."""
from flask import Blueprint, render_template

bp = Blueprint("pages", __name__)


@bp.route("/awareness")
def awareness():
    return render_template("awareness.html")


@bp.route("/about")
def about():
    return render_template("about.html")
