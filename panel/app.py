import csv
import hashlib
import io
import json
import logging
import os
import re
import secrets
import sqlite3
import ssl
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from flask import Flask, abort, jsonify, redirect, render_template_string, request, Response
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from werkzeug.exceptions import HTTPException

NS = os.environ.get("BG_NAMESPACE", "breakglass-system")
DB_PATH = os.environ.get("BG_DB", "/data/audit.db")
ANN = os.environ.get("BG_DOMAIN", "breakglass.acme.io")   # prefixo das anotações e labels (igual ao da VAP)
LABEL_REQ = f"{ANN}/request"
LABEL_GRANT = f"{ANN}/grant"
TEMP_GROUP = "breakglass-temp-cluster-admins"   # quem está aqui não aprova pedidos
CR_GROUP, CR_VERSION, CR_PLURAL = "breakglass.acme.io", "v1alpha1", "breakglassgrants"   # CRD do operator
MAX_MINUTES = 1440   # 24 h
MIN_MINUTES = 5
TICKET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{2,31}$")
DURATION_RE = re.compile(r"^(\d{1,3})([mh])$")
RID_RE = re.compile(r"^bgreq-[0-9a-f]{12}$")
GRANT_RE = re.compile(r"^(?:[a-z0-9]([-a-z0-9]*[a-z0-9])?/)?breakglass-grant-[a-z0-9-]{1,120}$")
NS_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")

# Fonte dos comandos executados: gateway do LokiStack (OpenShift Logging), tenant "audit".
# Exemplo: https://lokistack-gateway-http.openshift-logging.svc:8080/api/logs/v1/audit
# Vazio = aba mostra "fonte não configurada".
LOKI_URL = os.environ.get("BG_LOKI_URL", "").rstrip("/")
# CA de serviço do OpenShift (ConfigMap openshift-service-ca.crt montado em /etc/loki-ca)
LOKI_CA = os.environ.get("BG_LOKI_CA", "/etc/loki-ca/service-ca.crt")
SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"

# Catálogo de permissões que podem ser solicitadas.
# scope: "cluster" (CRB) ou "namespace" (RoleBinding no projeto)
ROLE_CATALOG = {
    "cluster-admin": {"scope": "cluster", "desc": "Acesso total ao cluster (equivale a root na API)"},
    "cluster-status": {"scope": "cluster", "desc": "Ver status do cluster: nós, operators e versão, sem alterar"},
    "cluster-reader": {"scope": "cluster", "desc": "Leitura de quase todos os recursos, sem Secrets"},
    "admin": {"scope": "namespace", "desc": "Gerencia um projeto inteiro, inclusive os acessos"},
    "edit": {"scope": "namespace", "desc": "Cria e altera recursos do projeto, sem mexer em acessos"},
    "view": {"scope": "namespace", "desc": "Somente leitura do projeto, sem Secrets"},
}
EVENTS = [
    "request_created", "request_approved", "request_denied", "self_approval_blocked",
    "decision_denied_not_approver", "grant_created", "grant_revoked", "grant_expired",
    "revoke_denied_not_approver", "audit_exported", "grant_create_failed",
]

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("breakglass-panel")

# O pod roda como a SA breakglass-portal (permissões em rbac base)
config.load_incluster_config()
panel_core = client.CoreV1Api()
panel_rbac = client.RbacAuthorizationV1Api()
panel_auth = client.AuthenticationV1Api()     # TokenReview
panel_authz = client.AuthorizationV1Api()     # SubjectAccessReview
panel_custom = client.CustomObjectsApi()     # Group user.openshift.io (grupo temporário)

app = Flask(__name__)


# ---------- banco de auditoria (SQLite no PVC) ----------

_db_lock = threading.Lock()

def db_exec(sql, params=(), fetch=False):
    with _db_lock:
        conn = sqlite3.connect(DB_PATH, timeout=15)
        try:
            conn.row_factory = sqlite3.Row
            cur = conn.execute(sql, params)
            rows = [dict(r) for r in cur.fetchall()] if fetch else None
            conn.commit()
            return rows
        finally:
            conn.close()

def init_db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    db_exec("""CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        event TEXT NOT NULL,
        actor TEXT,
        subject TEXT,
        request_id TEXT,
        grant_name TEXT,
        ticket TEXT,
        details TEXT)""")
    db_exec("CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts)")
    db_exec("CREATE INDEX IF NOT EXISTS ix_events_grant ON events(grant_name)")
    # uma única expiração por concessão, mesmo com corrida entre processos
    db_exec("CREATE UNIQUE INDEX IF NOT EXISTS ux_grant_expired ON events(grant_name) WHERE event='grant_expired'")

init_db()


# ---------- utilitários ----------

def now_dt():
    return datetime.now(timezone.utc)

def now_iso():
    return now_dt().isoformat(timespec="seconds")

def audit(event, actor="", subject="", request_id="", grant="", ticket="", **details):
    """Grava no stdout (SIEM) e no banco (histórico permanente). Se o banco falhar, a ação falha."""
    ts = now_iso()
    payload = {"ts": ts, "event": event, "actor": actor, "subject": subject,
               "request_id": request_id, "grant": grant, "ticket": ticket, **details}
    log.info(json.dumps(payload, ensure_ascii=False))
    db_exec("INSERT INTO events(ts,event,actor,subject,request_id,grant_name,ticket,details) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (ts, event, actor, subject, request_id, grant, ticket,
             json.dumps(details, ensure_ascii=False)))

def err(msg, code=400):
    return jsonify(error=msg), code

@app.errorhandler(HTTPException)
def handle_http(e):
    return jsonify(error=e.description), e.code

@app.before_request
def csrf_guard():
    # Formulários cross-site não conseguem definir este cabeçalho customizado
    if request.method == "POST" and request.headers.get("X-Requested-With") != "fetch":
        abort(403, "requisição sem cabeçalho de proteção CSRF")


def current_user():
    """Valida o token OAuth (repassado pelo oauth-proxy) com TokenReview. Retorna (usuário, grupos)."""
    token = request.headers.get("X-Forwarded-Access-Token")
    if not token:
        log.info(json.dumps({"ts": now_iso(), "event": "session_missing_token", "path": request.path}))
        abort(401, "sem sessão OAuth; acesse pela página de entrada")
    try:
        tr = panel_auth.create_token_review(
            client.V1TokenReview(spec=client.V1TokenReviewSpec(token=token)))
    except ApiException as e:
        log.info(json.dumps({"ts": now_iso(), "event": "token_review_error",
                             "status": e.status, "reason": e.reason, "path": request.path}))
        abort(401, "sessão inválida ou expirada")
    if not (tr.status and tr.status.authenticated):
        abort(401, "sessão inválida ou expirada")
    return tr.status.user.username, list(tr.status.user.groups or [])

def is_approver(user, groups):
    """Aprovador = cluster-admin (verbo * em recurso *) que NÃO está no grupo temporário."""
    if TEMP_GROUP in groups:
        return False
    review = client.V1SubjectAccessReview(spec=client.V1SubjectAccessReviewSpec(
        user=user, groups=groups,
        resource_attributes=client.V1ResourceAttributes(group="*", resource="*", verb="*")))
    return bool(panel_authz.create_subject_access_review(review).status.allowed)

def _set_temp_member(user, present):
    """Adiciona ou remove o usuário do grupo cluster-admin temporário."""
    g = panel_custom.get_cluster_custom_object("user.openshift.io", "v1", "groups", TEMP_GROUP)
    users = [u for u in (g.get("users") or []) if u != user]
    if present:
        users.append(user)
    g["users"] = users
    panel_custom.replace_cluster_custom_object("user.openshift.io", "v1", "groups", TEMP_GROUP, g)

def _active_admin_grants(user, exclude=""):
    """CRBs de cluster-admin ainda existentes para o usuário (exceto a concessão 'exclude')."""
    sel = f"{LABEL_GRANT}=true"
    out = []
    for c in panel_rbac.list_cluster_role_binding(label_selector=sel).items:
        a = c.metadata.annotations or {}
        if c.metadata.name != exclude and a.get(f"{ANN}/role") == "cluster-admin" \
                and a.get(f"{ANN}/requested-by") == user:
            out.append(c.metadata.name)
    return out

def _sync_temp_member(user, exclude=""):
    """Mantém o usuário no grupo só enquanto ele tiver alguma concessão de cluster-admin."""
    _set_temp_member(user, bool(_active_admin_grants(user, exclude)))


def parse_minutes(s):
    m = DURATION_RE.match(s or "")
    if not m:
        raise ValueError("duração inválida (use 15m, 1h, 8h, 24h...)")
    minutes = int(m.group(1)) * (60 if m.group(2) == "h" else 1)
    if not MIN_MINUTES <= minutes <= MAX_MINUTES:
        raise ValueError(f"duração deve ficar entre {MIN_MINUTES} min e {MAX_MINUTES} min")
    return minutes

def namespace_exists(ns):
    try:
        panel_core.read_namespace(ns)
        return True
    except ApiException as e:
        if e.status == 404:
            return False
        raise

def list_namespaces():
    """Nomes de projetos para o autocompletar, sem os namespaces de sistema."""
    names = [n.metadata.name for n in panel_core.list_namespace().items]
    def is_system(n):
        return n in ("default", "kube", NS) or n.startswith(("openshift", "kube-"))
    return sorted(n for n in names if not is_system(n))

def read_cm(rid):
    if not RID_RE.match(rid):
        abort(404, "solicitação não encontrada")
    try:
        return panel_core.read_namespaced_config_map(rid, NS)
    except ApiException as e:
        abort(404 if e.status == 404 else 500, "solicitação não encontrada")

def save_cm(cm, data):
    """Replace com resourceVersion: lock otimista (409 se alguém alterou antes)."""
    cm.data = data
    return panel_core.replace_namespaced_config_map(cm.metadata.name, NS, cm)

def list_requests():
    cms = panel_core.list_namespaced_config_map(NS, label_selector=f"{LABEL_REQ}=true").items
    reqs = [{"id": c.metadata.name, **(c.data or {})} for c in cms]
    reqs.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    return reqs

def _grant_row(obj, ns, now):
    a = obj.metadata.annotations or {}
    expires = a.get(f"{ANN}/expires-at", "")
    name = obj.metadata.name
    return {
        "id": f"{ns}/{name}" if ns else name,
        "namespace": ns or "(cluster)",
        "name": name,
        "role": a.get(f"{ANN}/role", ""),
        "requester": a.get(f"{ANN}/requested-by", ""),
        "approver": a.get(f"{ANN}/approved-by", ""),
        "ticket": a.get(f"{ANN}/ticket", ""),
        "duration": a.get(f"{ANN}/duration", ""),
        "request_id": a.get(f"{ANN}/request-id", ""),
        "expires_at": expires,
        "active": expires > now,
    }

def _cr_row(obj, now):
    s = obj.get("spec") or {}
    st = obj.get("status") or {}
    name = obj["metadata"]["name"]
    expires = s.get("expiresAt", "")
    phase = st.get("phase", "")
    ns = s.get("namespace") or ""
    return {
        "id": name,
        "namespace": ns or "(cluster)",
        "name": name,
        "role": s.get("role", ""),
        "requester": s.get("requester", ""),
        "approver": s.get("approver", ""),
        "ticket": s.get("ticket", ""),
        "duration": f"{s.get('durationMinutes', '')}m",
        "request_id": s.get("requestId", ""),
        "expires_at": expires,
        "active": phase == "Active" and expires > now,
        "phase": phase,
    }

def list_grants():
    """Concessões (CRs BreakglassGrant). O operator cria e expira os bindings."""
    now = now_iso()
    items = panel_custom.list_namespaced_custom_object(CR_GROUP, CR_VERSION, NS, CR_PLURAL).get("items", [])
    out = [_cr_row(i, now) for i in items]
    out.sort(key=lambda g: g["expires_at"], reverse=True)
    return out

def create_grant(rid, requester, approver, role, namespace, minutes, ticket, reason):
    """Cria o CR BreakglassGrant. O operator cria o binding e o grupo em segundos."""
    slug = re.sub(r"[^a-z0-9]+", "-", requester.lower()).strip("-")[:30] or "user"
    now = now_dt()
    name = f"breakglass-grant-{slug}-{int(now.timestamp())}"
    expires = (now + timedelta(minutes=minutes)).isoformat(timespec="seconds")
    body = {
        "apiVersion": f"{CR_GROUP}/{CR_VERSION}",
        "kind": "BreakglassGrant",
        "metadata": {"name": name, "namespace": NS},
        "spec": {
            "requester": requester,
            "approver": approver,
            "role": role,
            "namespace": namespace if ROLE_CATALOG[role]["scope"] == "namespace" else "",
            "ticket": ticket,
            "reason": reason,
            "durationMinutes": minutes,
            "expiresAt": expires,
            "requestId": rid,
        },
    }
    panel_custom.create_namespaced_custom_object(CR_GROUP, CR_VERSION, NS, CR_PLURAL, body)
    return name, expires

def revoke_grant(ident, actor):
    """Revoga na hora: remove o binding agora e apaga o CR (o operator confere e limpa o grupo)."""
    try:
        cr = panel_custom.get_namespaced_custom_object(CR_GROUP, CR_VERSION, NS, CR_PLURAL, ident)
    except ApiException as e:
        abort(404 if e.status == 404 else 500, "concessão não encontrada")
    s = cr.get("spec") or {}
    rid = s.get("requestId", "")
    requester = s.get("requester", "")
    ticket = s.get("ticket", "")
    role = s.get("role", "")
    ns = s.get("namespace", "") if ROLE_CATALOG.get(role, {}).get("scope") == "namespace" else ""
    try:
        if ns:
            panel_rbac.delete_namespaced_role_binding(ident, ns)
        else:
            panel_rbac.delete_cluster_role_binding(ident)
    except ApiException as e:
        if e.status != 404:
            abort(500, "não foi possível remover o acesso agora")
    try:
        panel_custom.delete_namespaced_custom_object(CR_GROUP, CR_VERSION, NS, CR_PLURAL, ident)
    except ApiException as e:
        if e.status != 404:
            abort(500, "não foi possível revogar a concessão")
    if RID_RE.match(rid):
        try:
            cm = panel_core.read_namespaced_config_map(rid, NS)
            d = dict(cm.data or {})
            d.update(status="revoked", revoked_by=actor, revoked_at=now_iso())
            save_cm(cm, d)
        except ApiException:
            log.info(json.dumps({"ts": now_iso(), "event": "revoke_status_update_failed",
                                 "request_id": rid, "grant": ident}))
    audit("grant_revoked", actor=actor, subject=requester, request_id=rid,
          grant=ident, ticket=ticket, role=role, namespace=ns or "(cluster)")

def granted_users():
    """Usuários que já receberam alguma permissão pelo painel."""
    users = {h["subject"] for h in grant_history() if h["subject"]}
    users |= {g["requester"] for g in list_grants() if g["requester"]}
    return sorted(users)

def parse_local(s):
    """Campo datetime-local, interpretado em UTC."""
    return datetime.strptime(s, "%Y-%m-%dT%H:%M").replace(tzinfo=timezone.utc)

def fetch_commands(users, user_filter, start, end, verb_f, ns_f):
    """Busca no Loki os eventos de auditoria do kube-apiserver dos usuários com permissão.
    O corpo de cada linha é o evento de auditoria padrão do Kubernetes (campos user, impersonatedUser,
    verb, objectRef, responseStatus). Se o forwarder envelopar em 'message', o código também lê."""
    if not LOKI_URL:
        raise RuntimeError("fonte de auditoria não configurada (BG_LOKI_URL)")
    names = [user_filter] if user_filter else users
    if not names:
        return []
    names = [n for n in names if "`" not in n]
    # Filtro literal para um usuário é bem mais rápido que regex sobre todos os logs
    if len(names) == 1:
        filt = '|= `"username":"' + names[0] + '"`'
    else:
        pattern = "|".join(re.escape(n) for n in names)
        filt = '|~ `"username":"(' + pattern + ')"`'
    query = '{log_type="audit"} ' + filt
    params = {
        "query": query,
        "start": str(int(start.timestamp() * 1e9)),
        "end": str(int(end.timestamp() * 1e9)),
        "limit": "1000",
        "direction": "backward",
    }
    url = f"{LOKI_URL}/loki/api/v1/query_range?{urllib.parse.urlencode(params)}"
    with open(SA_TOKEN_PATH) as fh:
        token = fh.read().strip()
    ctx = ssl.create_default_context(cafile=LOKI_CA if os.path.exists(LOKI_CA) else None)
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, context=ctx, timeout=90) as resp:
        data = json.load(resp)

    rows = []
    for stream in (data.get("data") or {}).get("result", []):
        for _ts, line in stream.get("values", []):
            try:
                ev = json.loads(line)
                if isinstance(ev, dict) and isinstance(ev.get("message"), str):
                    ev = json.loads(ev["message"])
            except (ValueError, TypeError):
                continue
            if not isinstance(ev, dict):
                continue
            ref = ev.get("objectRef") or {}
            row = {
                "ts": ev.get("requestReceivedTimestamp", ""),
                "user": (ev.get("user") or {}).get("username", ""),
                "impersonated": (ev.get("impersonatedUser") or {}).get("username", ""),
                "verb": ev.get("verb", ""),
                "resource": ref.get("resource", ""),
                "name": ref.get("name", ""),
                "namespace": ref.get("namespace", ""),
                "code": (ev.get("responseStatus") or {}).get("code", ""),
            }
            if verb_f and row["verb"] != verb_f:
                continue
            if ns_f and row["namespace"] != ns_f:
                continue
            rows.append(row)
    rows.sort(key=lambda r: r["ts"], reverse=True)
    return rows

def db_events(q="", ev="", user=None, limit=500):
    sql = "SELECT * FROM events WHERE 1=1"
    params = []
    if ev:
        sql += " AND event=?"
        params.append(ev)
    if user:
        sql += " AND (actor=? OR subject=?)"
        params += [user, user]
    if q:
        sql += " AND (actor LIKE ? OR subject LIKE ? OR grant_name LIKE ? OR ticket LIKE ? OR request_id LIKE ?)"
        params += [f"%{q}%"] * 5
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    return db_exec(sql, params, fetch=True)

def grant_history():
    """Uma linha por concessão, montada a partir dos eventos (criação, revogação, expiração)."""
    rows = db_exec("SELECT * FROM events WHERE event IN ('grant_created','grant_revoked','grant_expired') ORDER BY id",
                   fetch=True)
    by = {}
    for r in rows:
        g = by.setdefault(r["grant_name"], {
            "grant": r["grant_name"], "subject": "", "approver": "", "ticket": "", "role": "",
            "namespace": "", "request_id": "", "duration": "", "created_at": "", "expires_at": "",
            "status": "ativa", "ended_at": "", "ended_by": ""})
        det = json.loads(r["details"] or "{}")
        if r["event"] == "grant_created":
            g.update(subject=r["subject"], approver=r["actor"], ticket=r["ticket"],
                     request_id=r["request_id"], duration=det.get("duration", ""),
                     role=det.get("role", ""), namespace=det.get("namespace", "(cluster)"),
                     created_at=r["ts"], expires_at=det.get("expires_at", ""))
        elif r["event"] == "grant_revoked":
            g.update(status="revogada", ended_at=r["ts"], ended_by=r["actor"])
        elif r["event"] == "grant_expired":
            g.update(status="expirada", ended_at=r["ts"], ended_by="sistema")
    now = now_iso()
    for g in by.values():
        if g["status"] == "ativa" and g["expires_at"] and g["expires_at"] <= now:
            g["status"] = "vencida"
    return sorted(by.values(), key=lambda g: g["created_at"], reverse=True)

def expiry_watcher():
    """Registra no histórico as concessões que venceram, antes do expirer removê-las."""
    while True:
        try:
            for g in list_grants():
                if g["active"]:
                    continue
                seen = db_exec("SELECT 1 AS x FROM events WHERE event='grant_expired' AND grant_name=?",
                               (g["id"],), fetch=True)
                if not seen:
                    audit("grant_expired", actor="sistema", subject=g["requester"],
                          grant=g["id"], ticket=g["ticket"], request_id=g["request_id"],
                          approver=g["approver"], role=g["role"], namespace=g["namespace"],
                          expires_at=g["expires_at"])
        except Exception as e:  # o worker não pode morrer
            log.info(json.dumps({"ts": now_iso(), "event": "expiry_watcher_error",
                                 "error": type(e).__name__, "detail": str(e)[:300]}))
        time.sleep(60)

threading.Thread(target=expiry_watcher, daemon=True).start()


# ---------- rotas ----------

@app.get("/healthz")
def healthz():
    return "ok"

@app.get("/")
def landing():
    # Página de entrada pública. O botão leva ao login OAuth do cluster.
    if request.headers.get("X-Forwarded-Access-Token"):
        return redirect("/dashboard")
    return render_template_string(LOGIN_PAGE)

def _ctx():
    user, groups = current_user()
    return user, is_approver(user, groups)

def _render(view, title, approver, user, **data):
    data.setdefault("event_names", EVENTS)
    return render_template_string(DASH_PAGE, view=view, title=title, user=user, me=user,
                                  approver=approver, roles=ROLE_CATALOG, **data)

@app.get("/api/state")
def api_state():
    # Impressão digital dos pedidos e concessões. A página consulta isso e só recarrega
    # o conteúdo quando muda. Não expõe nada além de ids e status.
    current_user()
    snap = [[r.get("id"), r.get("status", "")] for r in list_requests()]
    snap += [[g["id"], g["active"]] for g in list_grants()]
    return {"fp": hashlib.sha1(json.dumps(snap).encode()).hexdigest()}

@app.get("/dashboard")
def dashboard():
    # Tela de solicitação: todos veem. Mostra só os pedidos do próprio usuário.
    user, approver = _ctx()
    reqs = [r for r in list_requests() if r.get("requester") == user]
    return _render("request", "Solicitar permissão", approver, user,
                   reqs=reqs, namespaces=list_namespaces())

@app.get("/approvals")
def approvals_view():
    # Só cluster-admin (identidade do próprio usuário, não impersonation)
    user, approver = _ctx()
    if not approver:
        return redirect("/dashboard")
    reqs = [r for r in list_requests() if r.get("requester") != user]
    grants = list_grants()
    counts = {
        "pending": sum(1 for r in reqs if r.get("status") == "pending"),
        "active": sum(1 for g in grants if g["active"]),
        "total": len(reqs),
    }
    return _render("approvals", "Aprovar solicitações", approver, user, reqs=reqs, counts=counts)

@app.get("/grants")
def grants_view():
    user, approver = _ctx()
    if not approver:
        return redirect("/dashboard")
    grants = list_grants()
    if not approver:
        grants = [g for g in grants if g["requester"] == user]
    return _render("grants", "Concessões ativas", approver, user, grants=grants)

@app.get("/history")
def history_view():
    user, approver = _ctx()
    if not approver:
        return redirect("/dashboard")
    q = (request.args.get("q") or "").strip().lower()
    st = request.args.get("status") or ""
    hist = grant_history()
    if not approver:
        hist = [h for h in hist if h["subject"] == user]
    if q:
        hist = [h for h in hist if q in " ".join([h["subject"], h["approver"], h["ticket"],
                                                  h["grant"], h["role"]]).lower()]
    if st:
        hist = [h for h in hist if h["status"] == st]
    return _render("history", "Histórico de concessões", approver, user, hist=hist, q=q, st=st)

@app.get("/audit")
def audit_view():
    user, approver = _ctx()
    if not approver:
        return redirect("/dashboard")
    q = (request.args.get("q") or "").strip()
    ev = request.args.get("ev") or ""
    events = db_events(q=q, ev=ev, user=None if approver else user)
    return _render("audit", "Auditoria", approver, user, events=events, q=q, ev_f=ev,
                   event_names=EVENTS)

@app.get("/audit.csv")
def audit_csv():
    user, approver = _ctx()
    if not approver:
        abort(403, "só aprovadores exportam a auditoria")
    rows = db_exec("SELECT ts,event,actor,subject,request_id,grant_name,ticket,details "
                   "FROM events ORDER BY id", fetch=True)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ts", "event", "actor", "subject", "request_id", "grant", "ticket", "details"])
    for r in rows:
        w.writerow([r["ts"], r["event"], r["actor"], r["subject"], r["request_id"],
                    r["grant_name"], r["ticket"], r["details"]])
    audit("audit_exported", actor=user, rows=len(rows))
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=breakglass-audit.csv"})

@app.get("/manual")
def manual_view():
    # Manual de configuração do Loki e do OpenShift Logging: só cluster-admin
    user, approver = _ctx()
    if not approver:
        return redirect("/dashboard")
    return _render("manual", "Manual de configuração", approver, user)

@app.get("/commands")
def commands_view():
    # Só cluster-admin vê os comandos executados pelos usuários com permissão
    user, approver = _ctx()
    if not approver:
        return redirect("/dashboard")
    f_user = (request.args.get("user") or "").strip()
    f_verb = (request.args.get("verb") or "").strip()
    f_ns = (request.args.get("ns") or "").strip()
    f_from = (request.args.get("de") or "").strip()
    f_to = (request.args.get("ate") or "").strip()
    try:
        end = parse_local(f_to) if f_to else now_dt()
        start = parse_local(f_from) if f_from else end - timedelta(hours=1)
    except ValueError:
        return err("data inválida")
    users = granted_users()
    rows, error = [], ""
    # Só consulta o Loki quando o usuário clica em Pesquisar; abrir a aba não traz logs
    searched = request.args.get("buscar") == "1"
    if searched:
        try:
            rows = fetch_commands(users, f_user, start, end, f_verb, f_ns)
        except Exception as e:
            hint = " A consulta demorou demais: tente um período menor (por exemplo, 1 hora)." if "timed out" in str(e) else ""
            error = f"não foi possível consultar a auditoria: {str(e)[:200]}.{hint}"
        audit("commands_viewed", actor=user, subject=f_user, rows=len(rows), verb=f_verb,
              namespace=f_ns, start=start.isoformat(timespec="seconds"), end=end.isoformat(timespec="seconds"))
    return _render("commands", "Auditoria de Usuários", approver, user, rows=rows, error=error,
                   users=users, f_user=f_user, f_verb=f_verb, f_ns=f_ns, f_from=f_from, f_to=f_to,
                   loki_ready=bool(LOKI_URL), searched=searched)

@app.post("/requests")
def create_request():
    user, _ = current_user()
    f = request.form
    role = (f.get("role") or "cluster-admin").strip()
    namespace = (f.get("namespace") or "").strip().lower()
    ticket = (f.get("ticket") or "").strip()
    reason = (f.get("reason") or "").strip()
    if role not in ROLE_CATALOG:
        return err("permissão inválida")
    if ROLE_CATALOG[role]["scope"] == "namespace":
        if not NS_RE.match(namespace):
            return err("informe o namespace (projeto) da permissão")
        if not namespace_exists(namespace):
            return err(f"o namespace '{namespace}' não existe")
    else:
        namespace = ""
    try:
        minutes = parse_minutes((f.get("duration") or "").strip())
    except ValueError as e:
        return err(str(e))
    if not TICKET_RE.match(ticket):
        return err("ticket inválido (ex.: INC0012345)")
    if not 10 <= len(reason) <= 300:
        return err("motivo deve ter entre 10 e 300 caracteres")

    rid = "bgreq-" + secrets.token_hex(6)
    cm = client.V1ConfigMap(
        metadata=client.V1ObjectMeta(name=rid, namespace=NS, labels={LABEL_REQ: "true"}),
        data={
            "requester": user,
            "role": role,
            "namespace": namespace,
            "minutes": str(minutes),
            "ticket": ticket,
            "reason": reason,
            "status": "pending",
            "created_at": now_iso(),
        },
    )
    panel_core.create_namespaced_config_map(NS, cm)
    audit("request_created", actor=user, subject=user, request_id=rid, ticket=ticket,
          role=role, namespace=namespace or "(cluster)", duration=f"{minutes}m", reason=reason)
    return jsonify(ok=True, id=rid)

def decide(rid, action):
    user, groups = current_user()
    if not is_approver(user, groups):
        audit("decision_denied_not_approver", actor=user, request_id=rid, action=action)
        abort(403, "você não é aprovador de break-glass")

    cm = read_cm(rid)
    d = dict(cm.data or {})
    if d.get("status") != "pending":
        return err("solicitação já decidida ou em processamento", 409)
    if d.get("requester") == user:
        audit("self_approval_blocked", actor=user, subject=user, request_id=rid)
        return err("você não pode decidir a própria solicitação", 403)

    role = d.get("role") or "cluster-admin"
    namespace = d.get("namespace", "")

    # 1) reivindica a solicitação (pending -> processing) com lock otimista
    d.update(status="processing", decided_by=user, decided_at=now_iso())
    try:
        cm = save_cm(cm, d)
    except ApiException as e:
        if e.status == 409:
            return err("outro aprovador decidiu antes", 409)
        raise

    if action == "deny":
        d["status"] = "denied"
        save_cm(cm, d)
        audit("request_denied", actor=user, subject=d["requester"], request_id=rid,
              ticket=d.get("ticket", ""), role=role)
        return jsonify(ok=True)

    # 2) cria a concessão
    try:
        grant, expires = create_grant(rid, d["requester"], user, role, namespace,
                                      int(d["minutes"]), d["ticket"], d["reason"])
    except ApiException as e:
        # reverte para pending para outro aprovador tentar de novo
        d.update(status="pending", decided_by="", decided_at="")
        try:
            save_cm(cm, d)
        except ApiException:
            log.info(json.dumps({"ts": now_iso(), "event": "revert_failed_manual_check", "request_id": rid}))
        audit("grant_create_failed", actor=user, request_id=rid, role=role, reason=e.reason, status=e.status)
        return err(f"falha ao criar a concessão: {e.reason}", 502)

    # 3) marca como aprovada. Se isto falhar, a concessão existe e precisa ser conferida.
    d.update(status="approved", grant=grant)
    try:
        save_cm(cm, d)
    except ApiException:
        audit("status_update_failed_after_grant", actor=user, request_id=rid, grant=grant)
        return err("concessão criada, mas o status não foi salvo. Verifique " + grant, 500)

    audit("grant_created", actor=user, subject=d["requester"], request_id=rid, grant=grant,
          ticket=d["ticket"], role=role, namespace=namespace or "(cluster)",
          duration=f"{d['minutes']}m", expires_at=expires)
    audit("request_approved", actor=user, subject=d["requester"], request_id=rid,
          grant=grant, ticket=d["ticket"], role=role)
    return jsonify(ok=True, grant=grant)

@app.post("/requests/<rid>/approve")
def approve(rid):
    return decide(rid, "approve")

@app.post("/requests/<rid>/deny")
def deny(rid):
    return decide(rid, "deny")

@app.post("/grants/revoke")
def revoke():
    user, groups = current_user()
    ident = (request.form.get("grant") or "").strip()
    if not is_approver(user, groups):
        audit("revoke_denied_not_approver", actor=user, grant=ident)
        abort(403, "só aprovadores podem revogar")
    if not GRANT_RE.match(ident):
        abort(404, "concessão não encontrada")
    revoke_grant(ident, user)
    return jsonify(ok=True)


# ---------- páginas ----------

LOGIN_PAGE = """<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>STA · Supervised Temporary Access</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;font-family:"Red Hat Text",system-ui,-apple-system,"Segoe UI",sans-serif;
 background:radial-gradient(1100px 620px at 8% -12%,#4a0f0f 0%,transparent 60%),
            radial-gradient(900px 520px at 112% 112%,#2a2a2a 0%,transparent 62%),#151515;
 display:flex;align-items:center;justify-content:center;color:#151515;padding:24px}
.card{width:min(440px,100%);background:#fff;border-radius:12px;box-shadow:0 24px 60px rgba(0,0,0,.5);overflow:hidden}
.band{height:6px;background:linear-gradient(90deg,#ee0000,#7d1007)}
.inner{padding:40px 36px 30px}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:28px}
.mark{width:34px;height:34px;border-radius:8px;background:#ee0000;display:grid;place-items:center;color:#fff;font-weight:700;font-size:13px}
.brand b{font-size:15px;letter-spacing:.2px}
h1{font-size:23px;margin:0 0 10px;font-weight:600}
p.lead{margin:0 0 28px;color:#6a6e73;line-height:1.55;font-size:14.5px}
.btn{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;padding:13px 16px;border-radius:8px;background:#ee0000;color:#fff;font-size:15px;font-weight:600;text-decoration:none}
.btn:hover{background:#c9190b}
.note{margin-top:22px;font-size:12.5px;color:#6a6e73;line-height:1.5;border-top:1px solid #e6e6e6;padding-top:16px}
.foot{text-align:center;color:#8a8d90;font-size:12px;margin-top:20px}
</style></head><body>
<div>
<div class="card"><div class="band"></div><div class="inner">
 <div class="brand"><div class="mark">STA</div><b>Supervised Temporary Access</b></div>
 <h1>Acesso temporário privilegiado</h1>
 <p class="lead">Solicite elevação temporária de privilégios para um chamado. Os pedidos são aprovados por um administrador do cluster e expiram automaticamente.</p>
 <a class="btn" href="/oauth/start?rd=/dashboard">Entrar com OpenShift &rarr;</a>
 <div class="note">Acesso restrito a usuários autenticados no cluster. Todas as ações são registradas em auditoria permanente.</div>
</div></div>
<div class="foot" style="max-width:440px;margin:20px auto 0;color:#d2d2d2;line-height:1.5">
 <b>Ferramenta interna não oficial.</b> O STA não é um produto da Red Hat e não tem suporte oficial da Red Hat. Use por sua conta e risco e valide em ambiente de teste antes de usar em produção.
</div>
<div class="foot">STA · Supervised Temporary Access</div>
</div>
</body></html>"""

DASH_PAGE = """<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} · STA</title>
<style>
:root{
 --mast:#151515; --mast-tx:#ffffff;
 --nav:#ffffff; --nav-tx:#151515; --nav-muted:#6a6e73; --nav-hover:#f0f0f0; --nav-on:#e0e0e0; --nav-accent:#0066cc;
 --bg:#f0f0f0; --card:#ffffff; --text:#151515; --muted:#6a6e73;
 --link:#0066cc; --btn:#0066cc; --btn-hover:#004080; --danger:#c9190b; --ok:#3e8635; --warn:#f0ab00;
}
*{box-sizing:border-box}
body{margin:0;font-family:"Red Hat Text","RedHatText",system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;background:var(--bg);color:var(--text);font-size:14px;line-height:1.43}
a{color:var(--link);text-decoration:none}
a:hover{text-decoration:underline}
.mast{height:48px;background:var(--mast);color:var(--mast-tx);display:flex;align-items:center;justify-content:space-between;padding:0 16px;position:sticky;top:0;z-index:10}
.mast-l{display:flex;align-items:center;gap:14px}
.burger{width:30px;height:30px;display:grid;place-items:center;font-size:18px;opacity:.9}
.product{font-size:16px;font-weight:600;letter-spacing:.1px}
.product small{font-weight:400;color:#c7c7c7;margin-left:6px;font-size:13px}
.mast-r{display:flex;align-items:center;gap:16px;font-size:13.5px}
.mast-r .who{padding:6px 10px;border-radius:3px}
.mast-r a.out{color:#fff;border:1px solid #5c5c5c;border-radius:3px;padding:4px 10px;font-size:13px}
.mast-r a.out:hover{background:#2b2b2b;text-decoration:none}
.shell{display:grid;grid-template-columns:240px 1fr;min-height:calc(100vh - 48px)}
.nav{background:var(--nav);border-right:1px solid #e0e0e0;padding:10px 0;position:sticky;top:48px;height:calc(100vh - 48px);overflow:auto}
.nav h6{margin:14px 16px 6px;font-size:12px;font-weight:600;color:var(--nav-muted)}
.nav a{display:block;padding:8px 16px 8px 20px;color:var(--nav-tx);border-left:3px solid transparent;font-size:14px}
.nav a:hover{background:var(--nav-hover);text-decoration:none}
.nav a.on{background:var(--nav-on);border-left-color:var(--nav-accent);font-weight:600}
.main{padding:0 0 40px;min-width:0}
.page-head{background:#fff;border-bottom:1px solid #d2d2d2;padding:14px 24px 12px}
.crumbs{font-size:12.5px;color:var(--muted);margin-bottom:6px}
.page-head h1{margin:0;font-size:24px;font-weight:400;line-height:1.25}
.content{padding:20px 24px}
.card{background:#fff;border:1px solid #d2d2d2;border-radius:3px;margin-bottom:20px}
.card-head{padding:14px 16px;border-bottom:1px solid #e0e0e0;display:flex;align-items:center;justify-content:space-between;gap:12px}
.card-head h2{font-size:16px;font-weight:600;margin:0}
.card-body{padding:16px}
.stats{display:grid;grid-template-columns:repeat(3,minmax(160px,1fr));gap:16px;margin-bottom:20px}
.stat{background:#fff;border:1px solid #d2d2d2;border-radius:3px;padding:14px 16px}
.stat .n{font-size:28px;font-weight:400}
.stat .l{color:var(--muted);font-size:13px;margin-top:2px}
.stat.p{border-top:3px solid var(--warn)} .stat.a{border-top:3px solid var(--ok)} .stat.t{border-top:3px solid var(--nav-accent)}
form.new{display:flex;flex-wrap:wrap;gap:14px;align-items:flex-end}
form.new label{flex:1 1 170px}
form.new label.wide{flex:2 1 260px}
label{display:flex;flex-direction:column;gap:6px;font-size:13px;color:#151515;font-weight:600}
input,select{font:inherit;font-weight:400;padding:6px 8px;border:1px solid #8a8d90;border-bottom-color:#6a6e73;border-radius:3px;background:#fff;color:var(--text);min-height:34px}
input:focus,select:focus{outline:2px solid var(--nav-accent);outline-offset:0}
.hint{font-size:12.5px;color:var(--muted);font-weight:400}
.btn{font:inherit;font-size:14px;border:1px solid transparent;border-radius:3px;padding:6px 16px;cursor:pointer;font-weight:600;min-height:36px}
.btn-primary{background:var(--btn);color:#fff}
.btn-primary:hover{background:var(--btn-hover)}
.btn-sec{background:#fff;color:var(--text);border-color:#8a8d90}
.btn-sec:hover{background:#f0f0f0}
.btn-danger{background:var(--danger);color:#fff}
.btn-danger:hover{background:#a30f08}
.btn-ghost{background:#fff;color:var(--danger);border-color:var(--danger)}
.btn-ghost:hover{background:#fdf0ef}
.btn-ok{background:var(--ok);color:#fff}
.btn-ok:hover{background:#2c6b26}
.btn-sm{font-size:13px;padding:4px 10px;min-height:28px}
.toolbar{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;margin-bottom:14px}
.toolbar label{font-weight:400;color:var(--muted);font-size:12.5px}
table.pf{width:100%;border-collapse:collapse;min-width:760px}
table.pf th,table.pf td{text-align:left;padding:10px 12px;border-top:1px solid #e0e0e0;vertical-align:top}
table.pf thead th{font-size:13px;font-weight:600;color:#151515;background:#fff;border-top:none;border-bottom:1px solid #d2d2d2}
table.pf tbody tr:hover{background:#fafafa}
.mono{font-family:"Red Hat Mono",ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;color:#4f5255}
.tag{display:inline-flex;align-items:center;gap:6px;font-size:13px;white-space:nowrap}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.s-pending .dot{background:var(--warn)}
.s-approved .dot,.s-active .dot{background:var(--ok)}
.s-denied .dot,.s-revoked .dot,.s-expired .dot,.s-vencida .dot{background:var(--danger)}
.s-processing .dot,.s-info .dot{background:var(--nav-accent)}
.muted{color:var(--muted)}
.empty{padding:28px;text-align:center;color:var(--muted)}
.actions{display:flex;gap:6px;flex-wrap:wrap}
.hint-block{font-size:13px;color:var(--muted);margin:0 0 14px}
.manual{max-width:920px;line-height:1.55}
.manual h2{font-size:18px;font-weight:600;margin:26px 0 8px}
.manual h2:first-child{margin-top:0}
.manual pre{background:#f5f5f5;border:1px solid #d2d2d2;border-radius:3px;padding:12px;overflow:auto;font-size:12.5px;font-family:"Red Hat Mono",ui-monospace,Menlo,Consolas,monospace}
.manual .warn{background:#fdf1d6;border:1px solid #f0ab00;border-radius:3px;padding:10px 12px;margin:10px 0}
.manual code{font-family:"Red Hat Mono",ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;background:#f0f0f0;padding:1px 4px;border-radius:2px}
@media (max-width:1000px){.shell{grid-template-columns:1fr}.nav{display:none}.stats{grid-template-columns:1fr}}
</style></head><body>
<header class="mast">
 <div class="mast-l">
  <span class="burger">&#9776;</span>
  <span class="product">STA <small>Supervised Temporary Access</small></span>
 </div>
 <div class="mast-r">
  <span class="who">{{ user }}{% if approver %} &middot; cluster-admin{% endif %}</span>
  <a class="out" href="/oauth/sign_out?rd=/">Sair</a>
 </div>
</header>

<div style="background:#fdf1d6;color:#5a3e00;border-bottom:1px solid #f0ab00;padding:8px 16px;font-size:13px">
 <b>Ferramenta interna não oficial.</b> O STA não é um produto da Red Hat e não tem suporte oficial da Red Hat.
</div>
<div class="shell">
 <nav class="nav">
  <h6>Acesso</h6>
  <a href="/dashboard" class="{% if view=='request' %}on{% endif %}">Solicitar permissão</a>
  {% if approver %}
  <a href="/approvals" class="{% if view=='approvals' %}on{% endif %}">Aprovar solicitações</a>
  <h6>Permissões</h6>
  <a href="/grants" class="{% if view=='grants' %}on{% endif %}">Concessões ativas</a>
  <a href="/history" class="{% if view=='history' %}on{% endif %}">Histórico de concessões</a>
  <h6>Auditoria</h6>
  <a href="/audit" class="{% if view=='audit' %}on{% endif %}">Eventos</a>
  <a href="/commands" class="{% if view=='commands' %}on{% endif %}">Auditoria de Usuários</a>
  <a href="/manual" class="{% if view=='manual' %}on{% endif %}">Manual de configuração</a>
  {% endif %}
 </nav>

 <main class="main">
  <div class="page-head">
   <div class="crumbs"><a href="/dashboard">STA</a> / {{ title }}</div>
   <h1>{{ title }}</h1>
  </div>
  <div class="content" id="content">

  {% if view in ['request', 'approvals'] %}
   {% if view == 'approvals' %}
   <div class="stats">
    <div class="stat p"><div class="n">{{ counts.pending }}</div><div class="l">Pendentes</div></div>
    <div class="stat a"><div class="n">{{ counts.active }}</div><div class="l">Concessões ativas</div></div>
    <div class="stat t"><div class="n">{{ counts.total }}</div><div class="l">Solicitações registradas</div></div>
   </div>
   {% endif %}

   {% if view == 'request' %}
   <section class="card">
    <div class="card-head"><h2>Solicitar acesso temporário</h2></div>
    <div class="card-body">
     <p class="hint-block">{% if approver %}Você também pode solicitar, mas não aprova o próprio pedido.{% else %}Um administrador do cluster precisa aprovar o pedido.{% endif %}</p>
     <form class="new" id="new">
      <label>Permissão
       <select name="role" id="role">
        {% for k, v in roles.items() %}
         <option value="{{ k }}" data-scope="{{ v.scope }}">{{ k }}</option>
        {% endfor %}
       </select>
       <span class="hint" id="role-desc">{{ roles['cluster-admin'].desc }}</span>
      </label>
      <label>Namespace (projeto)
       <input name="namespace" id="ns" list="ns-list" autocomplete="off" placeholder="digite para buscar o projeto" disabled>
       <datalist id="ns-list">
        {% for n in namespaces %}<option value="{{ n }}"></option>{% endfor %}
       </datalist>
       <span class="hint">obrigatório para view, edit e admin</span>
      </label>
      <label>Duração
       <select name="duration">
        <option value="1h">1 hora</option><option value="4h">4 horas</option><option value="8h">8 horas</option><option value="24h" selected>24 horas (máximo)</option>
       </select></label>
      <label>Ticket
       <input name="ticket" required placeholder="INC0012345" pattern="[A-Za-z0-9][A-Za-z0-9-]{2,31}"></label>
      <label class="wide">Motivo
       <input name="reason" required minlength="10" maxlength="300" placeholder="Descreva a necessidade (10 a 300 caracteres)"></label>
      <button class="btn btn-primary">Solicitar</button>
     </form>
    </div>
   </section>
   {% endif %}

   <section class="card">
    <div class="card-head"><h2>{% if view == 'approvals' %}Solicitações para aprovar{% else %}Minhas solicitações{% endif %}</h2></div>
    <div style="overflow:auto">
    <table class="pf">
     <thead><tr><th>Criada em</th><th>Solicitante</th><th>Permissão</th><th>Namespace</th><th>Duração</th><th>Ticket</th><th>Motivo</th><th>Status</th><th>Decisão</th><th>Ações</th></tr></thead>
     <tbody>
     {% for r in reqs %}
      <tr>
       <td><span class="mono">{{ r.created_at }}</span></td>
       <td>{{ r.requester }}</td>
       <td>{{ r.role or 'cluster-admin' }}</td>
       <td>{{ r.namespace or '(cluster)' }}</td>
       <td>{{ r.minutes }} min</td>
       <td>{{ r.ticket }}</td>
       <td>{{ r.reason }}</td>
       <td><span class="tag s-{{ r.status }}"><span class="dot"></span>{{ r.status }}</span></td>
       <td>{% if r.decided_by %}{{ r.decided_by }}<br><span class="mono">{{ r.decided_at }}</span>{% endif %}</td>
       <td class="actions">
        {% if approver and r.status == 'pending' and r.requester != me %}
         <button class="btn btn-ok btn-sm" onclick="decide('{{ r.id }}','approve')">Aprovar</button>
         <button class="btn btn-ghost btn-sm" onclick="decide('{{ r.id }}','deny')">Negar</button>
        {% elif r.status == 'pending' and r.requester == me %}
         <span class="muted">aguardando aprovador</span>
        {% endif %}
       </td>
      </tr>
     {% else %}
      <tr><td colspan="10" class="empty">Nenhuma solicitação.</td></tr>
     {% endfor %}
     </tbody>
    </table>
    </div>
   </section>

  {% elif view == 'grants' %}
   <section class="card">
    <div class="card-head"><h2>Concessões no cluster</h2></div>
    <div style="overflow:auto">
    <table class="pf">
     <thead><tr><th>Usuário</th><th>Permissão</th><th>Namespace</th><th>Aprovado por</th><th>Ticket</th><th>Duração</th><th>Expira em</th><th>Situação</th><th>Ações</th></tr></thead>
     <tbody>
     {% for g in grants %}
      <tr>
       <td>{{ g.requester }}</td>
       <td>{{ g.role }}</td>
       <td>{{ g.namespace }}</td>
       <td>{{ g.approver }}</td>
       <td>{{ g.ticket }}</td>
       <td>{{ g.duration }}</td>
       <td><span class="mono">{{ g.expires_at }}</span></td>
       <td>{% if g.active %}<span class="tag s-active"><span class="dot"></span>ativa</span>{% else %}<span class="tag s-expired"><span class="dot"></span>vencida</span>{% endif %}</td>
       <td class="actions">{% if approver and g.active %}<button class="btn btn-danger btn-sm" onclick="revoke('{{ g.id }}')">Revogar agora</button>{% endif %}</td>
      </tr>
     {% else %}
      <tr><td colspan="9" class="empty">Nenhuma concessão vigente.</td></tr>
     {% endfor %}
     </tbody>
    </table>
    </div>
   </section>

  {% elif view == 'history' %}
   <form class="toolbar" method="get" action="/history">
    <label>Buscar (usuário, aprovador, ticket, permissão)<input name="q" value="{{ q }}" placeholder="ex.: caixa, edit, INC0012345"></label>
    <label>Situação
     <select name="status">
      <option value="">Todas</option>
      {% for s in ['ativa','vencida','revogada','expirada'] %}
       <option value="{{ s }}" {% if st==s %}selected{% endif %}>{{ s }}</option>
      {% endfor %}
     </select></label>
    <button class="btn btn-sec">Filtrar</button>
   </form>
   <section class="card">
    <div class="card-head"><h2>Histórico de concessões</h2></div>
    <div style="overflow:auto">
    <table class="pf">
     <thead><tr><th>Concedida em</th><th>Usuário</th><th>Permissão</th><th>Namespace</th><th>Aprovada por</th><th>Ticket</th><th>Duração</th><th>Expira em</th><th>Situação</th><th>Encerrada em</th><th>Encerrada por</th><th>Pedido</th></tr></thead>
     <tbody>
     {% for h in hist %}
      <tr>
       <td><span class="mono">{{ h.created_at }}</span></td>
       <td>{{ h.subject }}</td>
       <td>{{ h.role }}</td>
       <td>{{ h.namespace }}</td>
       <td>{{ h.approver }}</td>
       <td>{{ h.ticket }}</td>
       <td>{{ h.duration }}</td>
       <td><span class="mono">{{ h.expires_at }}</span></td>
       <td><span class="tag s-{{ 'active' if h.status=='ativa' else ('expired' if h.status in ['vencida','expirada'] else 'revoked') }}"><span class="dot"></span>{{ h.status }}</span></td>
       <td><span class="mono">{{ h.ended_at }}</span></td>
       <td>{{ h.ended_by }}</td>
       <td><span class="mono">{{ h.request_id }}</span></td>
      </tr>
     {% else %}
      <tr><td colspan="12" class="empty">Nenhuma concessão no histórico.</td></tr>
     {% endfor %}
     </tbody>
    </table>
    </div>
   </section>

  {% elif view == 'audit' %}
   <form class="toolbar" method="get" action="/audit">
    <label>Buscar (usuário, concessão, ticket, pedido)<input name="q" value="{{ q }}" placeholder="ex.: caixa"></label>
    <label>Evento
     <select name="ev">
      <option value="">Todos</option>
      {% for e in event_names %}
       <option value="{{ e }}" {% if ev_f==e %}selected{% endif %}>{{ e }}</option>
      {% endfor %}
     </select></label>
    <button class="btn btn-sec">Filtrar</button>
    {% if approver %}<a class="btn btn-sec" href="/audit.csv" style="text-decoration:none;line-height:22px">Exportar CSV</a>{% endif %}
   </form>
   <section class="card">
    <div class="card-head"><h2>Eventos (mais recentes primeiro, até 500)</h2></div>
    <div style="overflow:auto">
    <table class="pf">
     <thead><tr><th>Quando (UTC)</th><th>Evento</th><th>Ator</th><th>Usuário afetado</th><th>Concessão</th><th>Pedido</th><th>Ticket</th><th>Detalhes</th></tr></thead>
     <tbody>
     {% for e in events %}
      <tr>
       <td><span class="mono">{{ e.ts }}</span></td>
       <td>{{ e.event }}</td>
       <td>{{ e.actor }}</td>
       <td>{{ e.subject }}</td>
       <td><span class="mono">{{ e.grant_name }}</span></td>
       <td><span class="mono">{{ e.request_id }}</span></td>
       <td>{{ e.ticket }}</td>
       <td><span class="mono">{{ e.details }}</span></td>
      </tr>
     {% else %}
      <tr><td colspan="8" class="empty">Nenhum evento.</td></tr>
     {% endfor %}
     </tbody>
    </table>
    </div>
   </section>
  {% elif view == 'commands' %}
   <form class="toolbar" method="get" action="/commands">
    <input type="hidden" name="buscar" value="1">
    <label>Usuário
     <input name="user" list="cmd-users" value="{{ f_user }}" placeholder="ex.: caixa">
     <datalist id="cmd-users">{% for u in users %}<option value="{{ u }}"></option>{% endfor %}</datalist></label>
    <label>Ação
     <select name="verb">
      {% for v in ['', 'get', 'list', 'create', 'update', 'patch', 'delete'] %}
       <option value="{{ v }}" {% if f_verb==v %}selected{% endif %}>{{ v or 'todas' }}</option>
      {% endfor %}
     </select></label>
    <label>Namespace<input name="ns" value="{{ f_ns }}" placeholder="meu-projeto"></label>
    <label>De (UTC)<input type="datetime-local" name="de" value="{{ f_from }}"></label>
    <label>Até (UTC)<input type="datetime-local" name="ate" value="{{ f_to }}"></label>
    <button class="btn btn-sec">Pesquisar</button>
   </form>
   {% if error %}<p class="hint-block" style="color:var(--danger)">{{ error }}</p>{% endif %}
   <section class="card">
    <div class="card-head"><h2>Auditoria de Usuários: comandos executados com permissão</h2></div>
    <div style="overflow:auto">
    <table class="pf">
     <thead><tr><th>Quando (UTC)</th><th>Usuário</th><th>Via</th><th>Ação</th><th>Recurso</th><th>Nome</th><th>Namespace</th><th>Resultado HTTP</th></tr></thead>
     <tbody>
     {% for c in rows %}
      <tr>
       <td><span class="mono">{{ c.ts }}</span></td>
       <td>{{ c.user }}</td>
       <td>{{ c.impersonated or '—' }}</td>
       <td>{{ c.verb }}</td>
       <td>{{ c.resource }}</td>
       <td><span class="mono">{{ c.name }}</span></td>
       <td>{{ c.namespace }}</td>
       <td>{{ c.code }}</td>
      </tr>
     {% else %}
      <tr><td colspan="8" class="empty">{% if not searched %}Escolha os filtros e clique em Pesquisar para carregar os comandos.{% elif loki_ready %}Nenhum comando no período.{% else %}Fonte de auditoria não configurada. Instale o OpenShift Logging (LokiStack): o painel se conecta sozinho.{% endif %}</td></tr>
     {% endfor %}
     </tbody>
    </table>
    </div>
   </section>
  {% elif view == 'manual' %}
{% raw %}
   <section class="card">
    <div class="card-body manual">

<div class="warn"><b>Ferramenta interna não oficial.</b> O STA não é um produto da Red Hat e não tem suporte oficial. Este manual descreve uma configuração de referência. Confira sempre nomes de canal, versões, apiVersion e roles na documentação oficial da versão do seu OpenShift, em docs.redhat.com.</div>

<h2>Visão geral</h2>
<p>A auditoria da API (kube-apiserver) registra cada chamada: quem fez, se foi via impersonation (<code>--as</code>), a ação, o recurso, o namespace e o resultado. O OpenShift Logging recolhe essa auditoria e envia para o LokiStack. O STA consulta o Loki e mostra a aba "Auditoria de Usuários".</p>
<pre>kube-apiserver (audit) --&gt; ClusterLogForwarder --&gt; LokiStack --&gt; STA (aba Auditoria de Usuários)</pre>

<h2>1. Pré-requisitos</h2>
<ul>
 <li>Login como cluster-admin.</li>
 <li>Armazenamento de objetos compatível com S3 para o Loki (por exemplo, OpenShift Data Foundation com NooBaa, ou AWS S3).</li>
 <li>StorageClass padrão para os volumes do Loki. Confira com <code>oc get storageclass</code>.</li>
 <li>Versão do OpenShift Logging compatível com a sua versão do cluster. Confira a matriz de compatibilidade na documentação oficial.</li>
</ul>

<h2>2. Instalar o Loki Operator</h2>
<pre>apiVersion: v1
kind: Namespace
metadata:
  name: openshift-operators-redhat
  labels:
    openshift.io/cluster-monitoring: "true"
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: openshift-operators-redhat
  namespace: openshift-operators-redhat
spec: {}
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: loki-operator
  namespace: openshift-operators-redhat
spec:
  channel: stable-6.2          # confira o canal: oc get packagemanifest loki-operator -n openshift-marketplace
  name: loki-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
  installPlanApproval: Automatic</pre>
<p>Confira o estado com <code>oc get csv -n openshift-operators-redhat</code>. O status precisa ser <code>Succeeded</code>.</p>

<h2>3. Instalar o OpenShift Logging</h2>
<pre>apiVersion: v1
kind: Namespace
metadata:
  name: openshift-logging
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: openshift-logging
  namespace: openshift-logging
spec:
  upgradeStrategy: Default
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: cluster-logging
  namespace: openshift-logging
spec:
  channel: stable-6.2          # confira o canal compatível com o Loki Operator
  name: cluster-logging
  source: redhat-operators
  sourceNamespace: openshift-marketplace
  installPlanApproval: Automatic</pre>

<h2>4. Armazenamento do Loki (bucket S3)</h2>
<p>Crie o bucket no seu provedor e depois o segredo no namespace do logging. Troque os valores pelos seus.</p>
<pre>oc create secret generic logging-loki-s3 -n openshift-logging \
  --from-literal=bucketnames=NOME-DO-BUCKET \
  --from-literal=endpoint=https://s3.exemplo.local \
  --from-literal=access_key_id=CHAVE_DE_ACESSO \
  --from-literal=access_key_secret=SEGREDO_DE_ACESSO</pre>

<h2>5. Criar o LokiStack</h2>
<pre>apiVersion: loki.grafana.com/v1
kind: LokiStack
metadata:
  name: logging-loki
  namespace: openshift-logging
spec:
  size: 1x.extra-small         # escolha pelo tamanho do cluster
  storage:
    schemas:
      - version: v13
        effectiveDate: "2024-10-01"   # data anterior à instalação, conforme a documentação
    secret:
      name: logging-loki-s3
      type: s3
  storageClassName: gp3-csi    # troque pela sua StorageClass
  tenants:
    mode: openshift-logging</pre>
<p>Confira com <code>oc get lokistack -n openshift-logging</code> e <code>oc get pods -n openshift-logging</code>.</p>

<h2>6. Coletar e encaminhar a auditoria</h2>
<p>Crie a service account do coletor e dê a ela as roles de leitura de auditoria e de escrita no Loki. Os nomes das roles mudam entre versões, confira na documentação.</p>
<pre>oc create sa logcollector -n openshift-logging
oc adm policy add-cluster-role-to-user collect-audit-logs -z logcollector -n openshift-logging
oc adm policy add-cluster-role-to-user logging-collector-logs-writer -z logcollector -n openshift-logging</pre>
<p>Em seguida, crie o encaminhador de auditoria para o LokiStack:</p>
<pre>apiVersion: observability.openshift.io/v1
kind: ClusterLogForwarder
metadata:
  name: instance
  namespace: openshift-logging
spec:
  serviceAccount:
    name: logcollector
  inputs:
    - name: audit-logs
      type: audit              # confira o tipo de input na sua versão
  outputs:
    - name: lokistack-audit
      type: lokiStack
      lokiStack:
        target:
          name: logging-loki
          namespace: openshift-logging
        authentication:
          token:
            from: serviceAccount
      tls:
        ca:
          key: service-ca.crt
          configMapName: openshift-service-ca.crt
  pipelines:
    - name: audit-to-loki
      inputRefs:
        - audit-logs
      outputRefs:
        - lokistack-audit</pre>

<h2>7. Ligar o STA ao Loki</h2>
<p>Descubra o nome do gateway do LokiStack e defina a URL no painel:</p>
<pre>oc get svc -n openshift-logging | grep gateway

oc set env deployment/breakglass-panel -c app -n breakglass-system \
  BG_LOKI_URL=https://logging-loki-gateway-http.openshift-logging.svc:8080/api/logs/v1/audit</pre>
<p>A service account do STA precisa ler o caminho <code>/api/logs/v1/audit</code>. O <code>install-breakglass.sh</code> já cria essa permissão em <code>breakglass-panel-cluster</code>. Se a consulta der 403, confira o caminho exato que o gateway exige para o tenant audit.</p>

<h2>8. Conferir</h2>
<ol>
 <li>Confirme o encaminhador: <code>oc get clusterlogforwarder instance -n openshift-logging -o yaml</code>. As condições precisam estar sem erro.</li>
 <li>Gere um comando com a conta que recebeu a permissão, por exemplo <code>oc get nodes</code>, e confirme também no console.</li>
 <li>Abra a aba "Auditoria de Usuários" no STA. O comando precisa aparecer em alguns minutos.</li>
</ol>

<h2>Problemas comuns</h2>
<ul>
 <li><b>A aba mostra erro de autorização (403):</b> a service account do STA não tem a permissão do caminho de auditoria. Confira o nome exato do gateway e do caminho.</li>
 <li><b>A aba está vazia:</b> confirme que o encaminhador está sem erro, que o perfil de auditoria é <code>Default</code> ou superior (<code>oc get apiserver cluster -o jsonpath='{.spec.audit.profile}'</code>), e que o usuário tem concessão ativa ou histórico.</li>
 <li><b>Erro de certificado (TLS):</b> o painel usa a CA de serviço do OpenShift, montada a partir do ConfigMap <code>openshift-service-ca.crt</code> do projeto <code>breakglass-system</code>. Confira com <code>oc get cm openshift-service-ca.crt -n breakglass-system</code>. Se o ConfigMap não existir, o problema é a injeção da CA de serviço no projeto. Depois de corrigir, reinicie o painel com <code>oc rollout restart deployment/breakglass-panel -n breakglass-system</code>.</li>
 <li><b>O LokiStack não fica pronto:</b> confira o bucket, as credenciais do segredo e a StorageClass. O detalhe aparece em <code>oc describe lokistack logging-loki -n openshift-logging</code>.</li>
</ul>

<h2>Referências</h2>
<p>Documentação oficial do OpenShift Logging e do Loki Operator em docs.redhat.com, na versão do seu cluster. Este manual não substitui essa documentação.</p>

    </div>
   </section>
{% endraw %}
  {% endif %}

  </div>
 </main>
</div>

<script>
async function call(url, data) {
  const r = await fetch(url, {
    method: 'POST', credentials: 'same-origin',
    headers: {'X-Requested-With': 'fetch', 'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams(data || {})
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { alert(j.error || ('Erro ' + r.status)); return; }
  location.reload();
}
// Eventos por delegação: continuam valendo depois que o conteúdo é atualizado
const ROLES = {{ roles|tojson }};
function syncRole() {
  const sel = document.getElementById('role');
  if (!sel) return;
  const ns = document.getElementById('ns');
  const desc = document.getElementById('role-desc');
  const r = ROLES[sel.value];
  desc.textContent = r ? r.desc : '';
  const needNs = r && r.scope === 'namespace';
  ns.disabled = !needNs;
  ns.required = needNs;
  if (!needNs) ns.value = '';
}
document.addEventListener('change', e => { if (e.target.id === 'role') syncRole(); });
document.addEventListener('submit', e => {
  if (e.target.id !== 'new') return;
  e.preventDefault();
  call('/requests', Object.fromEntries(new FormData(e.target)));
});
syncRole();

// Atualização em tempo real: a página consulta a impressão digital e recarrega só o conteúdo quando muda
let lastFp = null;
async function liveTick() {
  if (document.hidden) return;
  const el = document.activeElement;
  const editing = el && ['INPUT', 'SELECT', 'TEXTAREA'].includes(el.tagName);
  try {
    const r = await fetch('/api/state', {credentials: 'same-origin', cache: 'no-store'});
    if (!r.ok) return;
    const {fp} = await r.json();
    if (lastFp === null) { lastFp = fp; return; }
    if (fp === lastFp || editing) return;
    const html = await (await fetch(location.pathname, {credentials: 'same-origin', cache: 'no-store'})).text();
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const nc = doc.getElementById('content');
    const cur = document.getElementById('content');
    if (nc && cur) { cur.innerHTML = nc.innerHTML; syncRole(); }
    lastFp = fp;
  } catch (e) { /* tenta de novo no próximo ciclo */ }
}
if (['request', 'approvals', 'grants'].includes({{ view|tojson }})) setInterval(liveTick, 4000);
function decide(id, action) {
  const verbo = action === 'approve' ? 'APROVAR' : 'NEGAR';
  if (confirm(verbo + ' a solicitação ' + id + '?')) call('/requests/' + id + '/' + action);
}
function revoke(id) {
  if (confirm('REVOGAR agora a concessão ' + id + '? O acesso é removido imediatamente.')) call('/grants/revoke', {grant: id});
}
</script>
</body></html>"""
