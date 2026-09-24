"""Collect the complete, statically knowable file closure of a workflow.

The collector is intentionally a composition layer. Workflow loading, skill
discovery, plugin resolution, and registry acquisition remain owned by their
existing modules; this module calls those APIs and turns their resolved paths
into one deterministic bundle namespace.
"""

from __future__ import annotations

import glob
import hashlib
import os
import stat
import subprocess
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Literal

from jinja2 import Environment, nodes

from conductor.bundle.errors import (
    BundleCapsError,
    BundleCycleError,
    BundleDynamicTemplateError,
    BundleError,
    BundleRootEscapeError,
    BundleSymlinkEscapeError,
    BundleUnfetchedError,
)
from conductor.bundle.model import (
    BundleDescriptor,
    BundleEntry,
    BundleEnvironmentLink,
    BundleManifest,
    BundleProvenance,
    GitProvenance,
    PluginProvenance,
    RegistryProvenance,
    compute_bundle_digest,
)
from conductor.config.environment import ResolvedEnvironment
from conductor.config.loader import IncludedFilesGraph, load_config_with_graph, resolve_env_vars
from conductor.config.schema import (
    AgentDef,
    HumanGateStepDef,
    QuestionsStepDef,
    WorkflowConfig,
    WorkflowStepDef,
)
from conductor.file_string import FileString
from conductor.filesystem import is_dir_strict, is_file_strict, stat_or_none
from conductor.plugins.agents import is_agent_candidate
from conductor.plugins.errors import PluginFetchError, PluginSourceUnavailableError
from conductor.plugins.manifest import (
    DEFAULT_MCP_FILE,
    PLUGIN_AGENTS_DIR,
    PLUGIN_MANIFESTS,
    PLUGIN_SKILLS_DIR,
    find_manifest,
    manifest_flavor,
)
from conductor.plugins.registry import ResolvedPlugin, resolve_plugins
from conductor.plugins.resolution import ResolvedSource, marketplaces_from, resolve_plugin_sources
from conductor.providers.capabilities import plugin_flavor_for
from conductor.registry.cache import (
    _meta_dir,
    _read_source_metadata,
    auto_fetch_relative_workflow,
    find_registry_cache_location,
    resolve_and_fetch,
)
from conductor.registry.errors import RegistryError
from conductor.registry.resolver import ResolvedRef, resolve_ref
from conductor.skills import ResolvedSkill, resolve_effective_skills

WarningSink = Callable[[str], None]

# Keep this equal to engine/workflow.py's MAX_SUBWORKFLOW_DEPTH and
# config/validator.py's _MAX_SUBWORKFLOW_VALIDATION_DEPTH.
MAX_SUBWORKFLOW_DEPTH = 10
MAX_BUNDLE_ENTRIES = 10_000
MAX_BUNDLE_BYTES = 512 * 1024 * 1024

_OriginKind = Literal[
    "workflow",
    "include",
    "jinja_include",
    "subworkflow",
    "subworkflow_registry",
    "skill",
    "plugin",
    "asset",
]


@dataclass(frozen=True)
class CollectedBundle:
    """A bundle manifest, descriptor, and materialization payload."""

    entries: tuple[BundleEntry, ...]
    manifest: BundleManifest
    descriptor: BundleDescriptor
    files: Mapping[str, bytes]
    links: Mapping[str, str]


@dataclass(frozen=True)
class _AdditionalRoot:
    path: Path
    authored: str
    index: int
    namespace: str


@dataclass(frozen=True)
class _WorkflowNode:
    path: Path
    config: WorkflowConfig
    graph: IncludedFilesGraph
    registry_ref: str | None


class _Collector:
    def __init__(
        self,
        workflow_path: Path,
        environment: ResolvedEnvironment | None,
        allow_network: bool,
        on_warning: WarningSink,
    ) -> None:
        self.root_workflow = Path(os.path.abspath(os.path.normpath(workflow_path.expanduser())))
        self.root_dir = self.root_workflow.parent
        self.environment = environment
        self.allow_network = allow_network
        self.on_warning = on_warning
        self.entries: dict[str, BundleEntry] = {}
        self.files: dict[str, bytes] = {}
        self.links: dict[str, str] = {}
        self.host_paths: dict[Path, str] = {}
        self.skills_topology: dict[str, str] = {}
        self.plugins_topology: dict[str, str] = {}
        self.registry_provenance: dict[str, RegistryProvenance] = {}
        self.plugin_provenance: dict[str, PluginProvenance] = {}
        self.incomplete: list[str] = []
        self.warnings: list[str] = []
        self.nodes: list[_WorkflowNode] = []
        self.additional_roots: list[_AdditionalRoot] = []
        self.dependency_roots: set[Path] = set()
        self._total_bytes = 0

    def warn(self, message: str) -> None:
        self.warnings.append(message)
        self.on_warning(message)

    def collect(self) -> CollectedBundle:
        root_config, root_graph = load_config_with_graph(self.root_workflow)
        root_stat = stat_or_none(self.root_workflow)
        if root_stat is None:
            raise BundleError(f"Root workflow file does not exist: {self.root_workflow}")
        self.nodes.append(_WorkflowNode(self.root_workflow, root_config, root_graph, None))
        self._walk_subworkflows(
            self.nodes[0],
            depth=0,
            chain=((root_stat.st_dev, root_stat.st_ino),),
            names=(self.root_workflow.name,),
        )
        self._prepare_additional_roots()

        for index, node in enumerate(self.nodes):
            self._collect_loader_graph(node, root=index == 0)
            self._collect_jinja(node)
            self._collect_assets(node)
            self._collect_agent_dependencies(node)

        discovered = sorted(
            detail.removeprefix("skill-discovery:")
            for entry in self.entries.values()
            if (detail := entry.origin_detail).startswith("skill-discovery:")
        )
        if discovered:
            self.warn(
                "Bundle closure contains machine-dependent discovered skills: "
                + ", ".join(discovered)
            )

        ordered = tuple(sorted(self.entries.values(), key=lambda item: item.logical_path))
        digest = compute_bundle_digest(ordered, self.skills_topology, self.plugins_topology)
        manifest = BundleManifest(
            version=1,
            bundle_digest=digest,
            entries=ordered,
            skills_topology=dict(sorted(self.skills_topology.items())),
            plugins_topology=dict(sorted(self.plugins_topology.items())),
        )
        root_record = self.nodes[0].graph[0]
        descriptor = BundleDescriptor(
            bundle_digest=digest,
            run_manifest_digest=None,
            workflow_digest=root_record.digest,
            environment=(
                BundleEnvironmentLink(
                    name=self.environment.name,
                    source=self.environment.source,
                    digest=self.environment.digest,
                )
                if self.environment is not None
                else None
            ),
            provenance=BundleProvenance(
                git=self._git_provenance(),
                registry=list(self.registry_provenance.values()),
                plugins=list(self.plugin_provenance.values()),
            ),
            incomplete=sorted(set(self.incomplete)),
            warnings=list(self.warnings),
        )
        return CollectedBundle(
            entries=ordered,
            manifest=manifest,
            descriptor=descriptor,
            files=MappingProxyType(dict(self.files)),
            links=MappingProxyType(dict(self.links)),
        )

    def _walk_subworkflows(
        self,
        node: _WorkflowNode,
        *,
        depth: int,
        chain: tuple[tuple[int, int], ...],
        names: tuple[str, ...],
    ) -> None:
        for step in self._workflow_steps(node.config):
            if depth >= MAX_SUBWORKFLOW_DEPTH:
                raise BundleError(
                    f"Sub-workflow depth cap ({MAX_SUBWORKFLOW_DEPTH}) exceeded at "
                    f"{step.workflow!r}. Reduce workflow nesting."
                )
            sub_path, resolved = self._resolve_subworkflow(step.workflow, node.path.parent)
            info = stat_or_none(sub_path)
            if info is None:
                raise BundleError(f"Sub-workflow file does not exist: {sub_path}")
            identity = (info.st_dev, info.st_ino)
            if identity in chain:
                cycle = " -> ".join((*names, sub_path.name))
                raise BundleCycleError(f"Circular sub-workflow reference detected: {cycle}")
            config, graph = load_config_with_graph(sub_path)
            registry_ref = step.workflow if resolved.kind in {"registry", "adhoc"} else None
            child = _WorkflowNode(sub_path, config, graph, registry_ref)
            self.nodes.append(child)
            if registry_ref is not None:
                self._record_registry_provenance(registry_ref, sub_path)
            self._walk_subworkflows(
                child,
                depth=depth + 1,
                chain=(*chain, identity),
                names=(*names, sub_path.name),
            )

    @staticmethod
    def _workflow_steps(config: WorkflowConfig) -> Iterable[WorkflowStepDef]:
        for step in config.agents:
            if isinstance(step, WorkflowStepDef):
                yield step
        for group in config.for_each:
            if isinstance(group.agent, WorkflowStepDef):
                yield group.agent

    def _resolve_subworkflow(self, reference: str, base_dir: Path) -> tuple[Path, ResolvedRef]:
        candidate = Path(os.path.abspath(os.path.normpath(base_dir / reference)))
        if is_file_strict(candidate):
            return candidate, ResolvedRef(kind="file", path=candidate)

        looks_like_file = "@" not in reference and (
            "/" in reference or "\\" in reference or candidate.suffix.lower() in {".yaml", ".yml"}
        )
        if looks_like_file:
            if not self.allow_network:
                if find_registry_cache_location(candidate) is not None:
                    raise BundleUnfetchedError(
                        f"Sub-workflow {reference!r} is missing from the registry cache and "
                        "network access is disabled.",
                        suggestion=(
                            "Fetch the parent workflow with network access to prime its siblings."
                        ),
                    )
            else:
                try:
                    fetched = auto_fetch_relative_workflow(candidate)
                except RegistryError as exc:
                    raise BundleUnfetchedError(
                        f"Failed to fetch relative sub-workflow {reference!r}: {exc}"
                    ) from exc
                if fetched is not None and is_file_strict(fetched):
                    return fetched, ResolvedRef(kind="file", path=fetched)

        try:
            resolved = resolve_ref(reference)
            if resolved.kind == "file":
                raise BundleError(f"Sub-workflow file not found: {candidate}")
            return resolve_and_fetch(resolved, allow_network=self.allow_network), resolved
        except RegistryError as exc:
            raise BundleUnfetchedError(
                f"Sub-workflow {reference!r} is not available for bundling: {exc}"
            ) from exc

    def _record_registry_provenance(self, reference: str, path: Path) -> None:
        location = find_registry_cache_location(path)
        if location is None:
            return
        metadata = _read_source_metadata(_meta_dir(location.registry_name, location.sha))
        resolved_sha = metadata.full_sha if metadata is not None else location.sha
        self.registry_provenance.setdefault(
            reference, RegistryProvenance(ref=reference, resolved_sha=resolved_sha)
        )

    def _prepare_additional_roots(self) -> None:
        seen_basenames: dict[str, str] = {}
        declaration_index = 0
        for node in self.nodes:
            bundle = node.config.workflow.bundle
            for authored in bundle.additional_roots if bundle is not None else ():
                expanded = Path(authored).expanduser()
                if not expanded.is_absolute():
                    expanded = node.path.parent / expanded
                root = Path(os.path.abspath(os.path.normpath(expanded)))
                if not is_dir_strict(root):
                    raise BundleError(
                        f"Declared workflow.bundle.additional_roots entry {authored!r} "
                        f"does not exist or is not a directory: {root}"
                    )
                basename = root.name
                previous = seen_basenames.get(basename)
                if previous is not None and previous != authored:
                    raise BundleError(
                        f"Additional roots {previous!r} and {authored!r} share basename "
                        f"{basename!r}.",
                        suggestion="Rename or narrow one declared additional root.",
                    )
                seen_basenames[basename] = authored
                self.additional_roots.append(
                    _AdditionalRoot(
                        path=root,
                        authored=authored,
                        index=declaration_index,
                        namespace=f"tree/roots/{declaration_index:02d}-{basename}",
                    )
                )
                declaration_index += 1

    def _collect_loader_graph(self, node: _WorkflowNode, *, root: bool) -> None:
        for index, record in enumerate(node.graph):
            if index == 0:
                if root:
                    kind: _OriginKind = "workflow"
                    detail = "workflow:root"
                elif find_registry_cache_location(record.path) is not None:
                    kind = "subworkflow_registry"
                    detail = f"subworkflow_registry:{node.registry_ref or record.path.name}"
                else:
                    kind = "subworkflow"
                    detail = f"subworkflow:{record.path.name}"
            else:
                kind = "include"
                detail = f"include:{record.logical_ref}"
            self._stage_local(record.path, kind, detail)

    def _collect_jinja(self, node: _WorkflowNode) -> None:
        visited: set[Path] = set()
        for value in self._file_strings(node.config):
            root = Path(os.path.abspath(os.path.normpath(value.source_path.parent)))
            self._scan_template(value.source_path, root, visited)

    @staticmethod
    def _file_strings(config: WorkflowConfig) -> Iterable[FileString]:
        steps = [*config.agents, *(group.agent for group in config.for_each)]
        for step in steps:
            if isinstance(step, AgentDef):
                for value in (step.prompt, step.system_prompt):
                    if isinstance(value, FileString):
                        yield value
            elif isinstance(step, (HumanGateStepDef, QuestionsStepDef)) and isinstance(
                step.prompt, FileString
            ):
                yield step.prompt

    def _scan_template(self, path: Path, search_root: Path, visited: set[Path]) -> None:
        normalized = Path(os.path.abspath(os.path.normpath(path)))
        identity = Path(os.path.realpath(normalized))
        if identity in visited:
            return
        visited.add(identity)
        try:
            source = resolve_env_vars(normalized.read_bytes().decode("utf-8"))
        except OSError as exc:
            raise BundleError(f"Jinja prompt file could not be read: {normalized}: {exc}") from exc
        tree = Environment().parse(source)
        for node in tree.find_all((nodes.Extends, nodes.Import, nodes.FromImport, nodes.Include)):
            construct = type(node).__name__.lower()
            targets = self._template_targets(node, normalized, construct)
            existing: list[Path] = []
            for target in targets:
                candidate = Path(os.path.abspath(os.path.normpath(search_root / target)))
                if is_file_strict(candidate):
                    existing.append(candidate)
            ignore_missing = isinstance(node, nodes.Include) and node.ignore_missing
            if not existing and not ignore_missing:
                rendered = ", ".join(repr(target) for target in targets)
                raise BundleError(
                    f"Jinja {construct} in prompt {normalized} references missing template "
                    f"{rendered}."
                )
            for candidate in existing:
                self._stage_local(
                    candidate,
                    "jinja_include",
                    f"jinja_include:{candidate.relative_to(search_root).as_posix()}",
                )
                self._scan_template(candidate, search_root, visited)

    @staticmethod
    def _template_targets(
        node: nodes.Extends | nodes.Import | nodes.FromImport | nodes.Include,
        prompt: Path,
        construct: str,
    ) -> list[str]:
        template = node.template
        if isinstance(template, nodes.Const) and isinstance(template.value, str):
            return [template.value]
        if isinstance(node, nodes.Include) and isinstance(template, (nodes.List, nodes.Tuple)):
            values: list[str] = []
            for item in template.items:
                if not isinstance(item, nodes.Const) or not isinstance(item.value, str):
                    break
                values.append(item.value)
            else:
                return values
        raise BundleDynamicTemplateError(
            f"Dynamic Jinja {construct} in prompt {prompt} at line {node.lineno} cannot be "
            "bundled statically.",
            suggestion="Use a literal template name or a static list of literal names.",
            file_path=str(prompt),
            line_number=node.lineno,
        )

    def _collect_assets(self, node: _WorkflowNode) -> None:
        bundle = node.config.workflow.bundle
        if bundle is None:
            return
        for pattern in bundle.assets:
            expanded = glob.glob(
                str(node.path.parent / pattern), recursive=True, include_hidden=False
            )
            for raw in sorted(expanded):
                path = Path(raw)
                if path.is_symlink() or is_file_strict(path):
                    self._stage_local(path, "asset", f"asset:{pattern}")

    def _collect_agent_dependencies(self, node: _WorkflowNode) -> None:
        runtime = node.config.workflow.runtime
        source_results: dict[str, ResolvedSource] = {}
        unavailable: set[str] = set()
        for name, source in runtime.plugin_sources.items():
            try:
                source_results.update(
                    resolve_plugin_sources(
                        {name: source},
                        base_dir=node.path.parent,
                        allow_network=self.allow_network,
                        on_warning=self.warn,
                    )
                )
            except PluginFetchError as exc:
                if self.allow_network:
                    raise
                unavailable.add(name)
                self.incomplete.append(f"plugin-source:{name}")
                self.warn(f"Plugin source {name!r} is not cached: {exc}")

        marketplaces = marketplaces_from(source_results)
        flavor = plugin_flavor_for(runtime.provider.name)
        steps = [*node.config.agents, *(group.agent for group in node.config.for_each)]
        for step in steps:
            if not isinstance(step, AgentDef):
                continue
            if step.skills is None:
                skill_entries = list(runtime.skills)
                discovery = runtime.skill_discovery
                sources = tuple(discovery.sources)
                exclude = tuple(discovery.exclude)
            else:
                skill_entries = list(step.skills)
                sources = ()
                exclude = ()
            if skill_entries or sources:
                skills = resolve_effective_skills(
                    skill_entries,
                    sources=sources,
                    exclude=exclude,
                    base_dir=node.path.parent,
                    on_warning=self.warn,
                )
                for skill in skills:
                    self._collect_skill(skill)

            plugin_entries = (
                list(step.plugins) if step.plugins is not None else list(runtime.plugins)
            )
            if unavailable:
                plugin_entries = [
                    entry
                    for entry in plugin_entries
                    if not self._uses_unavailable_source(entry.name, unavailable)
                ]
            if not plugin_entries:
                continue
            try:
                plugins = resolve_plugins(
                    plugin_entries,
                    base_dir=node.path.parent,
                    marketplaces=marketplaces,
                    declared_sources=unavailable,
                    flavor=flavor,
                    on_warning=self.warn,
                )
            except PluginSourceUnavailableError:
                continue
            for plugin in plugins:
                self._collect_plugin(plugin, flavor, source_results)

    @staticmethod
    def _uses_unavailable_source(entry: str, unavailable: set[str]) -> bool:
        return "@" in entry and entry.rsplit("@", 1)[1] in unavailable

    def _collect_skill(self, skill: ResolvedSkill) -> None:
        namespace = f"tree/skills/{skill.name}"
        self.dependency_roots.add(skill.directory)
        detail = f"skill-discovery:{skill.name}" if skill.discovered else f"skill:{skill.name}"
        for path in self._iter_tree(skill.directory):
            relative = path.relative_to(skill.directory).as_posix()
            self._stage(path, f"{namespace}/{relative}", "skill", detail)
        topology = f"{namespace}/SKILL.md"
        self._set_topology(self.skills_topology, skill.name, topology, "skill")

    def _collect_plugin(
        self,
        plugin: ResolvedPlugin,
        requested_flavor: Literal["copilot", "claude"] | None,
        sources: Mapping[str, ResolvedSource],
    ) -> None:
        manifest = find_manifest(plugin.root, prefer=requested_flavor)
        if manifest is None:
            raise BundleError(f"Resolved plugin {plugin.name!r} has no manifest at {plugin.root}")
        actual_flavor = manifest_flavor(manifest, plugin.root)
        namespace = f"tree/plugins/{plugin.name}"
        self.dependency_roots.add(plugin.root)
        matching_source = next(
            (
                source
                for source in sources.values()
                if plugin.root.is_relative_to(source.marketplace.root)
            ),
            None,
        )
        if matching_source is not None:
            origin = "cache" if matching_source.sha is not None else "path"
            sha = matching_source.sha
        elif plugin.source.startswith((".", "~", "/")) or "\\" in plugin.source:
            origin, sha = "path", None
        else:
            origin, sha = "installed", None
        origin_detail = f"plugin-{origin}:{plugin.name}"
        selected: set[Path] = set()
        for relative in PLUGIN_MANIFESTS:
            candidate = plugin.root / relative
            if is_file_strict(candidate):
                selected.add(candidate)
        mcp = plugin.root / DEFAULT_MCP_FILE
        if is_file_strict(mcp):
            selected.add(mcp)
        agents = plugin.root / PLUGIN_AGENTS_DIR
        if is_dir_strict(agents):
            for candidate in self._iter_tree(agents):
                if candidate.is_symlink() or (
                    is_file_strict(candidate) and is_agent_candidate(candidate.name, actual_flavor)
                ):
                    selected.add(candidate)
        skills = plugin.root / PLUGIN_SKILLS_DIR
        if is_dir_strict(skills):
            selected.update(self._iter_tree(skills))
        for path in sorted(selected, key=lambda item: item.as_posix()):
            relative = path.relative_to(plugin.root).as_posix()
            self._stage(
                path,
                f"{namespace}/{relative}",
                "plugin",
                origin_detail,
            )
        manifest_logical = f"{namespace}/{manifest.relative_to(plugin.root).as_posix()}"
        self._set_topology(self.plugins_topology, plugin.name, manifest_logical, "plugin")
        for skill in plugin.skills:
            self._set_topology(
                self.skills_topology,
                skill.name,
                f"{namespace}/{skill.directory.relative_to(plugin.root).as_posix()}/SKILL.md",
                "skill",
            )

        self.plugin_provenance.setdefault(
            plugin.name,
            PluginProvenance(
                name=plugin.name,
                flavor=actual_flavor,
                origin=origin,
                sha=sha,
            ),
        )

    @staticmethod
    def _set_topology(table: dict[str, str], name: str, path: str, kind: str) -> None:
        previous = table.get(name)
        if previous is not None and previous != path:
            raise BundleError(
                f"Two resolved {kind}s named {name!r} map to different bundle paths: "
                f"{previous!r} and {path!r}."
            )
        table[name] = path

    def _iter_tree(self, root: Path) -> Iterable[Path]:
        for directory, directories, filenames in os.walk(root, followlinks=False):
            current = Path(directory)
            symlink_dirs = [name for name in directories if (current / name).is_symlink()]
            directories[:] = sorted(name for name in directories if name not in symlink_dirs)
            for name in sorted(symlink_dirs):
                yield current / name
            for name in sorted(filenames):
                path = current / name
                if path.is_symlink() or is_file_strict(path):
                    yield path

    def _stage_local(self, path: Path, kind: _OriginKind, detail: str) -> None:
        logical, root_detail = self._local_logical_path(path)
        if root_detail is not None:
            detail = f"{detail};additional_root={root_detail}"
        self._stage(path, logical, kind, detail)

    def _local_logical_path(self, path: Path) -> tuple[str, str | None]:
        normalized = Path(os.path.abspath(os.path.normpath(path)))
        location = find_registry_cache_location(normalized)
        if location is not None:
            relative = normalized.relative_to(location.sha_root).as_posix()
            return f"tree/registry/{location.registry_name}/{location.sha}/{relative}", None
        try:
            relative = normalized.relative_to(self.root_dir).as_posix()
            return f"tree/main/{relative}", None
        except ValueError:
            pass
        for root in self.additional_roots:
            try:
                relative = normalized.relative_to(root.path).as_posix()
                return f"{root.namespace}/{relative}", root.authored
            except ValueError:
                continue
        raise BundleRootEscapeError(
            f"Bundle dependency {normalized} escapes every authorized root.",
            suggestion="Declare the root in workflow.bundle.additional_roots.",
            file_path=str(normalized),
        )

    def _stage(
        self,
        path: Path,
        logical_path: str,
        origin_kind: _OriginKind,
        origin_detail: str,
    ) -> None:
        normalized = Path(os.path.abspath(os.path.normpath(path)))
        self._assert_authorized(normalized)
        logical = PurePosixPath(logical_path).as_posix()
        if normalized.is_symlink():
            target = PurePosixPath(os.readlink(normalized).replace("\\", "/")).as_posix()
            resolved_target = Path(os.path.realpath(normalized))
            if not self._inside_authorized_root(resolved_target):
                raise BundleSymlinkEscapeError(
                    f"Symlink {normalized} points outside every authorized root to "
                    f"{resolved_target}.",
                    suggestion="Move the target inside an authorized root or declare its root.",
                )
            entry = BundleEntry.for_symlink(
                logical,
                target,
                origin_kind=origin_kind,
                origin_detail=origin_detail,
            )
            payload: bytes | str = target
        else:
            info = stat_or_none(normalized)
            if info is None or not stat.S_ISREG(info.st_mode):
                raise BundleError(f"Bundle dependency is not a regular file: {normalized}")
            raw = normalized.read_bytes()
            entry = BundleEntry(
                logical_path=logical,
                kind="file",
                digest=f"sha256:{hashlib.sha256(raw).hexdigest()}",
                size=len(raw),
                executable=bool(info.st_mode & stat.S_IXUSR),
                link_target=None,
                origin_kind=origin_kind,
                origin_detail=origin_detail,
            )
            payload = raw
        previous = self.entries.get(logical)
        if previous is not None:
            if previous.digest != entry.digest or previous.kind != entry.kind:
                raise BundleError(
                    f"Bundle logical path {logical!r} has contradictory content: "
                    f"{previous.digest} versus {entry.digest}."
                )
            return
        self.entries[logical] = entry
        self.host_paths[normalized] = logical
        if entry.kind == "file":
            assert isinstance(payload, bytes)
            self.files[logical] = payload
            self._total_bytes += len(payload)
        else:
            assert isinstance(payload, str)
            self.links[logical] = payload
        self._check_caps()

    def _assert_authorized(self, path: Path) -> None:
        if find_registry_cache_location(path) is not None:
            return
        candidate = path if path.is_symlink() else Path(os.path.realpath(path))
        roots = [
            self.root_dir,
            *(root.path for root in self.additional_roots),
            *self.dependency_roots,
        ]
        if not any(candidate.is_relative_to(root) for root in roots):
            raise BundleRootEscapeError(
                f"Bundle dependency {path} escapes every authorized root.",
                suggestion="Declare the root in workflow.bundle.additional_roots.",
            )

    def _inside_authorized_root(self, path: Path) -> bool:
        target = Path(os.path.realpath(path))
        if find_registry_cache_location(target) is not None:
            return True
        roots = [
            self.root_dir,
            *(root.path for root in self.additional_roots),
            *self.dependency_roots,
        ]
        return any(target.is_relative_to(Path(os.path.realpath(root))) for root in roots)

    def _check_caps(self) -> None:
        if len(self.entries) > MAX_BUNDLE_ENTRIES:
            raise BundleCapsError(
                f"Bundle entry cap exceeded: maximum {MAX_BUNDLE_ENTRIES}, "
                f"actual {len(self.entries)}."
            )
        if self._total_bytes > MAX_BUNDLE_BYTES:
            raise BundleCapsError(
                f"Bundle byte cap exceeded: maximum {MAX_BUNDLE_BYTES}, actual {self._total_bytes}."
            )

    def _git_provenance(self) -> GitProvenance | None:
        root_text = self._run_git("rev-parse", "--show-toplevel")
        if root_text is None:
            return None
        git_root = Path(root_text)
        head = self._run_git("rev-parse", "HEAD", cwd=git_root)
        remote = self._run_git("remote", "get-url", "origin", cwd=git_root)
        candidates: dict[str, str] = {}
        for host, logical in self.host_paths.items():
            try:
                candidates[host.relative_to(git_root).as_posix()] = logical
            except ValueError:
                continue
        dirty: list[str] = []
        if candidates:
            output = self._run_git(
                "status", "--porcelain=v1", "-z", "--", *sorted(candidates), cwd=git_root
            )
            if output is not None:
                records = output.split("\0")
                index = 0
                modified: set[str] = set()
                while index < len(records):
                    record = records[index]
                    index += 1
                    if not record:
                        continue
                    status_code = record[:2]
                    modified.add(record[3:])
                    if status_code[0] in {"R", "C"} and index < len(records):
                        modified.add(records[index])
                        index += 1
                dirty = sorted(candidates[path] for path in modified if path in candidates)
        return GitProvenance(head_sha=head, remote=remote, dirty=dirty)

    def _run_git(self, *args: str, cwd: Path | None = None) -> str | None:
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        try:
            result = subprocess.run(
                ["git", *args],
                cwd=cwd or self.root_dir,
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        return result.stdout.rstrip("\n")


def collect_bundle(
    workflow_path: Path,
    *,
    environment: ResolvedEnvironment | None,
    allow_network: bool,
    on_warning: WarningSink,
) -> CollectedBundle:
    """Collect a workflow's complete statically knowable file closure.

    Args:
        workflow_path: Root workflow YAML file.
        environment: Resolved execution environment link, if one was selected.
        allow_network: Whether registry and plugin-source cache misses may fetch.
        on_warning: Sink receiving every non-fatal diagnostic.

    Returns:
        Immutable entries/models plus regular-file and symlink payload maps.

    Raises:
        BundleError: If the closure is incomplete for any reason other than
            an offline plugin-source cache miss.
    """
    return _Collector(workflow_path, environment, allow_network, on_warning).collect()
