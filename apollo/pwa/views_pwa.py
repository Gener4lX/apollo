# -*- coding: utf-8 -*-
import logging
from http import HTTPStatus

from flask import (
    Blueprint,
    current_app,
    jsonify,
    make_response,
    render_template,
    request,
    send_from_directory,
    session,
)
from flask_babel import gettext as _
from flask_jwt_extended import create_access_token, set_access_cookies
from sqlalchemy import func

from apollo.core import csrf
from apollo.deployments.models import Event
from apollo.frontend import route
from apollo.participants.models import Participant, PhoneContact
from apollo.pwa.mobile_auth import (
    MobileAuthError,
    extract_bearer_token,
    mask_phone,
    phone_from_claims,
    phone_match_key,
    resolve_observer_phone,
    verify_deow_api_key,
    verify_wp_token,
)

blueprint = Blueprint("pwa", __name__, static_folder="static", template_folder="templates", url_prefix="/pwa")
logger = logging.getLogger(__name__)

# session key holding the ids of the participants the mobile user may choose from
MOBILE_CANDIDATES_KEY = "pwa_mobile_candidates"


def _base_context():
    commit = current_app.config["COMMIT"] or current_app.config["VERSION"]

    trace_errors = current_app.config["DEBUG"]
    sentry_dsn = current_app.config["SENTRY_DSN"] or ""

    context = {"commit": commit, "trace_errors": trace_errors, "mobile_bootstrap": None}
    if trace_errors:
        context.update(dsn=sentry_dsn)
    context["page_title"] = _("Apollo")

    return context


@route(blueprint, "/")
def index():
    """Index view for the PWA."""
    return render_template("pwa/index.html", **_base_context())


def _participant_payload(participant):
    """Same shape as the participant object returned by the participant login API."""
    return {
        "events": [ev.id for ev in participant.participant_set.events],
        "first_name": participant.first_name,
        "other_names": participant.other_names,
        "last_name": participant.last_name,
        "full_name": participant.full_name,
        "participant_id": participant.participant_id,
        "location": participant.location.name if participant.location else "",
        "locale": participant.locale,
    }


def _candidate_summary(participant):
    return {
        "participant_id": participant.participant_id,
        "full_name": participant.full_name,
        "location": participant.location.name if participant.location else "",
        "events": [ev.name for ev in participant.participant_set.events],
    }


def _find_participants_by_phone(match_key):
    """Participants in current events with a verified phone number ending in ``match_key``."""
    current_events = Event.overlapping_events(Event.default())
    digits = func.regexp_replace(PhoneContact.number, r"[^0-9]", "", "g")
    rows = (
        current_events.join(Participant, Participant.participant_set_id == Event.participant_set_id)
        .join(PhoneContact, PhoneContact.participant_id == Participant.id)
        .with_entities(Participant)
        .filter(PhoneContact.verified.is_(True), func.right(digits, 9) == match_key)
        .order_by(Participant.participant_id)
        .all()
    )

    # a participant set can belong to several overlapping events; remove duplicates
    seen = set()
    participants = []
    for participant in rows:
        if participant.id not in seen:
            seen.add(participant.id)
            participants.append(participant)

    return participants


def _mobile_error(message, status=HTTPStatus.UNAUTHORIZED):
    response = make_response(render_template("pwa/mobile_error.html", message=message, **_base_context()), status)
    response.headers["Cache-Control"] = "no-store"
    return response


@route(blueprint, "/mobile-auth")
def mobile_auth():
    """Sign an observer in from the DEOW mobile app using their verified phone number.

    The app authenticates with ``X-API-Key`` (or ``api_key`` query param) matching ``DEOW_API_KEY``
    and supplies the logged-in observer's phone number via ``X-Observer-Phone`` (or ``phone`` query
    param). The phone number is normalized (last 9 digits) and matched against verified participant
    phone contacts in the current event.
    """
    if not current_app.config.get("MOBILE_AUTH_ENABLED"):
        return _mobile_error(_("Mobile sign-in is not available."), HTTPStatus.NOT_FOUND)

    expected_api_key = current_app.config.get("DEOW_API_KEY", "")
    provided_api_key = request.headers.get("X-API-Key") or request.args.get("api_key")
    raw_phone = request.headers.get("X-Observer-Phone") or request.args.get("phone")

    try:
        if expected_api_key:
            verify_deow_api_key(provided_api_key, expected_api_key)
            phone = resolve_observer_phone(raw_phone)
        else:
            auth_header = request.headers.get("Authorization")
            if not auth_header and request.args.get("token"):
                auth_header = f"Bearer {request.args.get('token')}"
            token = extract_bearer_token(auth_header)
            claims = verify_wp_token(
                token, current_app.config["WP_JWT_SECRET"], current_app.config.get("WP_JWT_ISSUER", "")
            )
            phone = phone_from_claims(claims)
    except MobileAuthError as error:
        logger.warning("Mobile sign-in rejected: %s", error.message)
        return _mobile_error(
            _("Could not verify your sign-in (%(reason)s). Please log in to the DEOW app again.", reason=error.message),
            error.status,
        )

    match_key = phone_match_key(phone)
    participants = _find_participants_by_phone(match_key) if match_key else []
    if not participants:
        logger.info("Mobile sign-in: no participant for phone %s", mask_phone(phone))
        return _mobile_error(
            _("No observer record is linked to your phone number for the current event."),
            HTTPStatus.NOT_FOUND,
        )

    session[MOBILE_CANDIDATES_KEY] = [p.id for p in participants]
    session.permanent = True

    bootstrap = {"participant": None, "candidates": [_candidate_summary(p) for p in participants]}
    if len(participants) == 1:
        bootstrap["participant"] = _participant_payload(participants[0])

    context = _base_context()
    context["mobile_bootstrap"] = bootstrap
    response = make_response(render_template("pwa/index.html", **context))
    response.headers["Cache-Control"] = "no-store"

    if len(participants) == 1:
        set_access_cookies(response, create_access_token(identity=str(participants[0].uuid), fresh=True))

    return response


@route(blueprint, "/mobile-select", methods=["POST"])
@csrf.exempt
def mobile_select():
    """Sign in as one of the participants matched in :func:`mobile_auth`."""
    candidate_ids = session.get(MOBILE_CANDIDATES_KEY) or []
    payload = request.get_json(silent=True) or {}
    participant_id = payload.get("participant_id")

    participant = None
    if candidate_ids and participant_id:
        participant = (
            Participant.query.filter(Participant.id.in_(candidate_ids), Participant.participant_id == participant_id)
            .first()
        )

    if participant is None:
        response = jsonify({"status": "error", "message": _("Session expired")})
        response.status_code = HTTPStatus.UNAUTHORIZED
        return response

    response = jsonify(
        {
            "data": {"participant": _participant_payload(participant)},
            "status": "ok",
            "message": _("Logged in successfully"),
        }
    )
    set_access_cookies(response, create_access_token(identity=str(participant.uuid), fresh=True))
    response.headers["Cache-Control"] = "no-store"

    return response


@route(blueprint, "/serviceworker.js")
def service_worker():
    """Serve the service worker."""
    response = make_response(send_from_directory(blueprint.static_folder, path="js/serviceworker.js"))
    response.headers["Content-Type"] = "application/javascript"
    return response


@route(blueprint, "/versioncheck")
def version_check():
    """Version check endpoint for the PWA."""
    version = current_app.config["VERSION"]
    commit = current_app.config["COMMIT"] or version

    return jsonify({"version": version, "commit": commit})
