"""Tests for the scip_k8s indexer (k8s/Helm → SCIP).

helm/kustomize aren't available in unit-test env, so we stub ONLY the render
boundary (`_render`, the subprocess call) with REAL rendered-manifest YAML —
the parse + two-pass by-name resolution + SCIP emit all run for real. This is
deliberate: the terraform leg shipped a transport bug (LSP short-read) precisely
because its tests mocked the whole client; here we mock only the external
process and exercise every line of resolution logic.

Validates:
  * descriptor / symbol scheme
  * Deployment → ServiceAccount by-name resolution
  * RoleBinding subjects[] → SA and roleRef → Role
  * Pod → Secret (volume, envFrom, env.valueFrom.secretKeyRef)
  * Ingress → Service
  * unresolved refs (target defined elsewhere) are dropped, not emitted
  * the emitted .scip round-trips through scip_pb2 with correct def/ref roles
  * detection returns None without k8s config
"""
from __future__ import annotations

from pathlib import Path
from unittest import mock

from strix.tools.code_graph.scip_k8s import emit, indexer, scip_pb2


def test_descriptor_and_symbol_scheme():
    assert indexer._descriptor("default", "ServiceAccount", "foo") == \
        "default/ServiceAccount/foo#"
    assert indexer._descriptor("", "Role", "r") == "default/Role/r#"
    assert emit.make_symbol("default/ServiceAccount/foo#") == \
        "scip-k8s . . . default/ServiceAccount/foo#"


# --- reference extraction (pure, no render) ---------------------------------

def test_workload_serviceaccount_ref():
    dep = {"kind": "Deployment", "metadata": {"name": "web", "namespace": "app"},
           "spec": {"template": {"spec": {"serviceAccountName": "web-sa"}}}}
    assert ("ServiceAccount", "web-sa", "app") in indexer._references(dep)


def test_rolebinding_refs():
    rb = {"kind": "RoleBinding", "metadata": {"name": "b", "namespace": "app"},
          "roleRef": {"kind": "Role", "name": "reader"},
          "subjects": [{"kind": "ServiceAccount", "name": "web-sa"}]}
    refs = indexer._references(rb)
    assert ("Role", "reader", "app") in refs
    assert ("ServiceAccount", "web-sa", "app") in refs


def test_pod_secret_refs_all_shapes():
    pod = {"kind": "Pod", "metadata": {"name": "p", "namespace": "app"},
           "spec": {
               "serviceAccountName": "p-sa",
               "volumes": [{"name": "v", "secret": {"secretName": "vol-sec"}}],
               "containers": [{
                   "name": "c",
                   "envFrom": [{"secretRef": {"name": "envfrom-sec"}}],
                   "env": [{"name": "K", "valueFrom":
                            {"secretKeyRef": {"name": "keyref-sec", "key": "k"}}}],
               }]}}
    refs = indexer._references(pod)
    assert ("Secret", "vol-sec", "app") in refs
    assert ("Secret", "envfrom-sec", "app") in refs
    assert ("Secret", "keyref-sec", "app") in refs
    assert ("ServiceAccount", "p-sa", "app") in refs


def test_ingress_service_ref():
    ing = {"kind": "Ingress", "metadata": {"name": "i", "namespace": "app"},
           "spec": {"rules": [{"http": {"paths": [
               {"backend": {"service": {"name": "web-svc"}}}]}}]}}
    assert ("Service", "web-svc", "app") in indexer._references(ing)


# --- full pipeline over a real rendered stream (render stubbed) --------------

_RENDERED = """\
apiVersion: v1
kind: ServiceAccount
metadata:
  name: web-sa
  namespace: app
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: reader
  namespace: app
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: web-reader
  namespace: app
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: reader
subjects:
  - kind: ServiceAccount
    name: web-sa
    namespace: app
---
apiVersion: v1
kind: Secret
metadata:
  name: web-secret
  namespace: app
type: Opaque
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: app
spec:
  template:
    spec:
      serviceAccountName: web-sa
      volumes:
        - name: sec
          secret:
            secretName: web-secret
      containers:
        - name: c
          image: web:latest
"""


def _run_index(tmp_path: Path, rendered: str = _RENDERED):
    # a real render root so _discover_render_roots finds it
    (tmp_path / "kustomization.yaml").write_text("resources: []\n")
    out = tmp_path / "out"
    out.mkdir()
    with mock.patch.object(indexer, "_binary_exists", return_value=True), \
         mock.patch.object(indexer, "_render", return_value=rendered):
        return indexer.index(tmp_path, out)


def test_index_resolves_rbac_and_secret_chain(tmp_path):
    scip_path = _run_index(tmp_path)
    assert scip_path is not None
    idx = scip_pb2.Index()
    idx.ParseFromString(scip_path.read_bytes())

    # collect all occurrences across documents
    defs, refs = set(), []
    for d in idx.documents:
        for o in d.occurrences:
            if o.symbol_roles == emit.ROLE_DEFINITION:
                defs.add(o.symbol)
            else:
                refs.append(o.symbol)

    sa = emit.make_symbol("app/ServiceAccount/web-sa#")
    role = emit.make_symbol("app/Role/reader#")
    secret = emit.make_symbol("app/Secret/web-secret#")

    # definitions present
    assert {sa, role, secret} <= defs
    # cross-object references resolved to those definitions
    assert sa in refs      # Deployment→SA AND RoleBinding.subjects→SA
    assert role in refs    # RoleBinding.roleRef→Role
    assert secret in refs  # Deployment volume→Secret
    # SA is referenced twice (deployment + rolebinding subject)
    assert refs.count(sa) >= 2


def test_unresolved_refs_are_dropped(tmp_path):
    # SA lives in another repo → not defined here → its ref must NOT be emitted
    rendered = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: app
spec:
  template:
    spec:
      serviceAccountName: external-sa
      containers:
        - name: c
          image: web:latest
"""
    scip_path = _run_index(tmp_path, rendered)
    # Deployment is a definition, but the external-sa ref is unresolved → the
    # only content is the Deployment's own def symbol, no dangling ref.
    if scip_path is None:
        return  # acceptable: no resolvable content at all
    idx = scip_pb2.Index()
    idx.ParseFromString(scip_path.read_bytes())
    ext = emit.make_symbol("app/ServiceAccount/external-sa#")
    for d in idx.documents:
        for o in d.occurrences:
            assert o.symbol != ext  # never emit an unresolved ref


def test_index_returns_none_without_k8s(tmp_path):
    (tmp_path / "main.py").write_text("print('no k8s here')\n")
    assert indexer.index(tmp_path, tmp_path) is None


def test_remote_helmchart_kustomization_skipped(tmp_path):
    # v1 local-only: a kustomization that pulls from a remote helm repo must be
    # classified as remote-pull and NOT offered as a render root.
    remote = tmp_path / "svc"
    remote.mkdir()
    (remote / "kustomization.yaml").write_text(
        "kind: Kustomization\n"
        "helmCharts:\n"
        "  - name: baseline-app\n"
        "    repo: https://nexus.infra.0hash.com/repository/helm-internal\n"
        "    releaseName: svc\n"
    )
    local = tmp_path / "local"
    local.mkdir()
    (local / "kustomization.yaml").write_text("resources: []\n")

    assert indexer._needs_remote_pull(remote / "kustomization.yaml") is True
    assert indexer._needs_remote_pull(local / "kustomization.yaml") is False

    roots = indexer._discover_render_roots(tmp_path)
    root_dirs = {d for d, _ in roots}
    assert local in root_dirs        # self-contained → rendered
    assert remote not in root_dirs   # remote-pull → skipped (Phase 1.5)
