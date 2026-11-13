"""STA operator.

Recursos:
- BreakglassPanel (singleton "sta"): instala o painel (RBAC, políticas, PVC, Service, Route, Deployment).
- BreakglassGrant: concessão. Cria o binding, mantém o grupo temporário e expira.

O operator cria o namespace de trabalho e o CR BreakglassPanel padrão na inicialização.
"""
import base64
import os
import re
import secrets
from datetime import datetime, timezone

import kopf
import yaml
from kubernetes import client, config, dynamic
from kubernetes.client.rest import ApiException
from kubernetes.dynamic.exceptions import ConflictError

GROUP = "breakglass.acme.io"
VERSION = "v1alpha1"
GRANTS = "breakglassgrants"
PANELS = "breakglasspanels"
PANEL_CR = "sta"
DOMAIN = os.environ.get("BG_DOMAIN", "breakglass.acme.io")   # prefixo das anotações e labels
NS = os.environ.get("BG_NAMESPACE", "breakglass-system")      # namespace de trabalho
PANEL_IMAGE = os.environ.get("PANEL_IMAGE", "quay.io/marcruz/sta-panel:v0.1.0")
MANIFEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "manifests")
TEMP_GROUP = "breakglass-temp-cluster-admins"
LABEL_GRANT = f"{DOMAIN}/grant"
TICKET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{2,31}$")

# role -> escopo. cluster: ClusterRoleBinding; namespace: RoleBinding no projeto
ROLE_SCOPE = {
    "cluster-admin": "cluster",
    "cluster-status": "cluster",
    "cluster-reader": "cluster",
    "view": "namespace",
    "edit": "namespace",
    "admin": "namespace",
}

config.load_incluster_config()
core = client.CoreV1Api()
rbac = client.RbacAuthorizationV1Api()
custom = client.CustomObjectsApi()
dyn = dynamic.DynamicClient(client.ApiClient())


def now_dt():
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------- namespace e painel

def ensure_namespace():
    try:
        core.read_namespace(NS)
    except ApiException as e:
        if e.status != 404:
            raise
        try:
            core.create_namespace(client.V1Namespace(
                metadata=client.V1ObjectMeta(name=NS, labels={"breakglass.acme.io/managed": "true"})))
        except ApiException as ce:
            if ce.status != 409:
                raise


def ensure_cookie_secret():
    """Segredo do cookie do oauth-proxy: criado uma vez e nunca trocado (trocar derruba as sessões)."""
    try:
        core.read_namespaced_secret("breakglass-panel-cookie", NS)
    except ApiException as e:
        if e.status != 404:
            raise
        core.create_namespaced_secret(NS, client.V1Secret(
            metadata=client.V1ObjectMeta(name="breakglass-panel-cookie", namespace=NS),
            string_data={"cookie_secret": secrets.token_hex(16)}))


LOKI_NS = "openshift-logging"
LOKI_SVC = "logging-loki-gateway-http"
LOKI_AUDIT_PATH = "/api/logs/v1/audit"


def discover_loki():
    """Descobre o gateway do LokiStack (OpenShift Logging). Vazio se ainda não estiver instalado."""
    try:
        core.read_namespaced_service(LOKI_SVC, LOKI_NS)
    except ApiException as e:
        if e.status == 404:
            return ""
        raise
    return f"https://{LOKI_SVC}.{LOKI_NS}.svc:8080{LOKI_AUDIT_PATH}"


CONSOLE_LINK = "breakglass-sta"
ICON_B64 = base64.b64encode(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.svg"), "rb").read()).decode()


def ensure_console_link():
    """Atalho no menu de aplicações do console (ApplicationMenu), apontando para a Route do painel."""
    route = custom.get_namespaced_custom_object("route.openshift.io", "v1", NS, "routes", "breakglass-panel")
    host = route.get("spec", {}).get("host", "")
    if not host:
        raise kopf.TemporaryError("rota do painel ainda sem host", delay=10)
    body = {
        "apiVersion": "console.openshift.io/v1",
        "kind": "ConsoleLink",
        "metadata": {"name": CONSOLE_LINK},
        "spec": {
            "location": "ApplicationMenu",
            "text": "Painel STA",
            "href": f"https://{host}",
            "applicationMenu": {
                "section": "STA (não oficial)",
                "imageURL": f"data:image/svg+xml;base64,{ICON_B64}",
            },
        },
    }
    try:
        custom.create_cluster_custom_object("console.openshift.io", "v1", "consolelinks", body)
    except ApiException as e:
        if e.status != 409:
            raise
        custom.patch_cluster_custom_object("console.openshift.io", "v1", "consolelinks", CONSOLE_LINK, body)


def render(name, loki_url=""):
    text = open(os.path.join(MANIFEST_DIR, name)).read()
    text = text.replace("__DOMAIN__", DOMAIN).replace("__PANEL_IMAGE__", PANEL_IMAGE)
    docs = [d for d in yaml.safe_load_all(text) if d]
    if loki_url:
        for d in docs:
            if d["kind"] == "Deployment":
                app = d["spec"]["template"]["spec"]["containers"][0]
                app.setdefault("env", []).append({"name": "BG_LOKI_URL", "value": loki_url})
    return docs


def apply_docs(docs):
    """Cria o objeto; se já existir, aplica um merge patch. Idempotente."""
    for doc in docs:
        api = dyn.resources.get(api_version=doc["apiVersion"], kind=doc["kind"])
        ns = doc["metadata"].get("namespace")
        name = doc["metadata"]["name"]
        try:
            api.create(body=doc, namespace=ns)
        except ConflictError:
            api.patch(body=doc, name=name, namespace=ns, content_type="application/merge-patch+json")


def reconcile_platform(loki_url=""):
    ensure_namespace()
    ensure_cookie_secret()
    apply_docs(render("base.yaml"))
    apply_docs(render("policies.yaml"))
    apply_docs(render("panel.yaml", loki_url))


@kopf.on.startup()
def bootstrap(**_):
    """Cria o namespace e o CR BreakglassPanel padrão, para o STA funcionar só com a instalação."""
    try:
        ensure_namespace()
        try:
            custom.get_namespaced_custom_object(GROUP, VERSION, NS, PANELS, PANEL_CR)
        except ApiException as e:
            if e.status != 404:
                raise
            custom.create_namespaced_custom_object(GROUP, VERSION, NS, PANELS, {
                "apiVersion": f"{GROUP}/{VERSION}", "kind": "BreakglassPanel",
                "metadata": {"name": PANEL_CR, "namespace": NS}, "spec": {}})
    except ApiException as e:
        raise kopf.TemporaryError(f"bootstrap falhou: {e.status}", delay=15)


@kopf.on.create(GROUP, VERSION, PANELS)
@kopf.on.resume(GROUP, VERSION, PANELS)
def panel_reconcile(namespace, spec, patch, **_):
    if namespace != NS:
        return
    try:
        reconcile_platform(discover_loki())
    except ApiException as e:
        patch.status["phase"] = "Pending"
        patch.status["message"] = f"falha ao aplicar: {e.status} {e.reason}"
        raise kopf.TemporaryError("falha ao aplicar o painel", delay=20)
    ensure_console_link()
    patch.status["phase"] = "Ready"
    patch.status["message"] = ""


@kopf.timer(GROUP, VERSION, PANELS, interval=300.0, initial_delay=300.0)
def panel_drift(namespace, spec, status, **_):
    """Refaz a aplicação a cada 5 min: corrige alterações manuais e mantém BG_LOKI_URL do spec."""
    if namespace != NS or status.get("phase") != "Ready":
        return
    reconcile_platform(discover_loki())
    ensure_console_link()


# ---------------------------------------------------------------- concessões

def validate(spec):
    """Mesmas regras da VAP e do painel. Erro permanente: o CR fica como Rejected."""
    role = spec.get("role", "")
    if role not in ROLE_SCOPE:
        raise kopf.PermanentError(f"role não permitida: {role}")
    if spec.get("approver") == spec.get("requester"):
        raise kopf.PermanentError("o aprovador não pode ser o solicitante")
    minutes = int(spec.get("durationMinutes", 0))
    if not 5 <= minutes <= 1440:
        raise kopf.PermanentError("duração deve ficar entre 5 e 1440 minutos")
    if not TICKET_RE.match(spec.get("ticket", "")):
        raise kopf.PermanentError("ticket inválido")
    if ROLE_SCOPE[role] == "namespace":
        ns = spec.get("namespace", "")
        if not ns or ns.startswith(("openshift", "kube-")) or ns == NS:
            raise kopf.PermanentError("namespace inválido para concessão de projeto")


def annotations_for(spec):
    return {
        f"{DOMAIN}/requested-by": spec["requester"],
        f"{DOMAIN}/approved-by": spec["approver"],
        f"{DOMAIN}/ticket": spec["ticket"],
        f"{DOMAIN}/reason": spec.get("reason", ""),
        f"{DOMAIN}/duration": f"{int(spec['durationMinutes'])}m",
        f"{DOMAIN}/request-id": spec.get("requestId", ""),
        f"{DOMAIN}/expires-at": spec["expiresAt"],
        f"{DOMAIN}/role": spec["role"],
    }


def ensure_binding(name, spec):
    role = spec["role"]
    labels = {LABEL_GRANT: "true"}
    annotations = annotations_for(spec)
    subject = client.RbacV1Subject(api_group="rbac.authorization.k8s.io", kind="User", name=spec["requester"])
    role_ref = client.V1RoleRef(api_group="rbac.authorization.k8s.io", kind="ClusterRole", name=role)
    try:
        if ROLE_SCOPE[role] == "namespace":
            obj = client.V1RoleBinding(
                metadata=client.V1ObjectMeta(name=name, namespace=spec["namespace"],
                                             labels=labels, annotations=annotations),
                role_ref=role_ref, subjects=[subject])
            rbac.create_namespaced_role_binding(spec["namespace"], obj)
        else:
            obj = client.V1ClusterRoleBinding(
                metadata=client.V1ObjectMeta(name=name, labels=labels, annotations=annotations),
                role_ref=role_ref, subjects=[subject])
            rbac.create_cluster_role_binding(obj)
    except ApiException as e:
        if e.status != 409:   # 409 = já existe (reexecução do handler)
            raise kopf.TemporaryError(f"falha ao criar binding: {e.status}", delay=10)


def remove_binding(name, spec):
    try:
        if ROLE_SCOPE[spec["role"]] == "namespace":
            rbac.delete_namespaced_role_binding(name, spec["namespace"])
        else:
            rbac.delete_cluster_role_binding(name)
    except ApiException as e:
        if e.status != 404:
            raise kopf.TemporaryError(f"falha ao remover binding: {e.status}", delay=10)


def set_temp_member(user, present):
    """Adiciona ou remove o usuário do grupo cluster-admin temporário."""
    g = custom.get_cluster_custom_object("user.openshift.io", "v1", "groups", TEMP_GROUP)
    users = [u for u in (g.get("users") or []) if u != user]
    if present:
        users.append(user)
    g["users"] = users
    custom.replace_cluster_custom_object("user.openshift.io", "v1", "groups", TEMP_GROUP, g)


def other_active_admin_grants(user, exclude_name):
    items = custom.list_namespaced_custom_object(GROUP, VERSION, NS, GRANTS).get("items", [])
    return [i for i in items
            if i["metadata"]["name"] != exclude_name
            and i.get("spec", {}).get("requester") == user
            and i.get("spec", {}).get("role") == "cluster-admin"
            and i.get("status", {}).get("phase") == "Active"]


def release_admin_membership(user, exclude_name):
    """Sai do grupo só se o usuário não tiver outra concessão de cluster-admin ativa."""
    if not other_active_admin_grants(user, exclude_name):
        set_temp_member(user, False)


@kopf.on.create(GROUP, VERSION, GRANTS)
@kopf.on.resume(GROUP, VERSION, GRANTS)
def grant_created(name, namespace, spec, status, patch, **_):
    if namespace != NS or status.get("phase") in ("Expired", "Rejected"):
        return
    try:
        validate(spec)
    except kopf.PermanentError as e:
        patch.status["phase"] = "Rejected"
        patch.status["message"] = str(e)
        return
    # cluster-admin entra no grupo antes do binding: sem grupo, não há concessão
    if spec["role"] == "cluster-admin":
        set_temp_member(spec["requester"], True)
    ensure_binding(name, spec)
    patch.status["phase"] = "Active"
    patch.status["binding"] = name
    patch.status["message"] = ""


@kopf.timer(GROUP, VERSION, GRANTS, interval=15.0)
def grant_expiry(name, namespace, spec, status, patch, **_):
    if namespace != NS or status.get("phase") != "Active":
        return
    expires = datetime.fromisoformat(spec["expiresAt"])
    if expires > now_dt():
        return
    remove_binding(name, spec)
    if spec["role"] == "cluster-admin":
        release_admin_membership(spec["requester"], name)
    patch.status["phase"] = "Expired"


@kopf.on.delete(GROUP, VERSION, GRANTS)
def grant_deleted(name, namespace, spec, **_):
    if namespace != NS:
        return
    remove_binding(name, spec)
    if spec.get("role") == "cluster-admin":
        release_admin_membership(spec["requester"], name)
