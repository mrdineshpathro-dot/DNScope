"""Rule engine: turns evidence-backed observations into findings.

Rules are data, not code paths. Each YAML document names a registered logic check
and declares the severity, confidence, recommendation and references that apply
when that check fires. That keeps the analytic logic testable in isolation and
lets an operator retune severity without editing Python.

Two invariants are enforced here rather than trusted to individual rules:

* a finding without evidence is dropped
* a rule whose logic check is unknown is reported, never silently skipped
"""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator

from dnscope.exceptions import RuleError
from dnscope.models.common import Confidence, SchemaVersioned, Severity
from dnscope.models.findings import Finding, RuleReference
from dnscope.rules.context import RuleHit, ScanContext
from dnscope.rules.logic import get_logic, registered_logic
from dnscope.utils.ids import new_id
from dnscope.utils.logging import get_logger
from dnscope.utils.time_utils import utc_now_iso

_log = get_logger("rules.engine")

#: Directory shipped with DNScope that holds the built-in rule packs.
BUILTIN_RULES_DIR = Path(__file__).resolve().parents[2] / "rules"

#: Rule categories, mirroring the ``rules/`` file names.
CATEGORIES = (
    "dns",
    "dnssec",
    "email",
    "certificates",
    "infrastructure",
    "takeover",
    "enterprise",
)


class RuleSpec(SchemaVersioned):
    """A declarative rule definition."""

    rule_id: str
    title: str
    logic: str
    severity: Severity = Severity.LOW
    confidence: Confidence = Confidence.MEDIUM
    description: str = ""
    recommendation: str = ""
    category: str = "dns"
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    enabled: bool = True
    #: ``builtin`` | ``yaml`` | ``plugin`` | ``custom``.
    source: str = "builtin"
    #: Path the rule was loaded from (empty for built-ins registered in code).
    path: str = ""
    #: Only fire for observations whose id is in this list (used by the generic
    #: ``intelligence_observations`` check).
    match: list[str] = Field(default_factory=list)
    #: Minimum evidence quality required before the rule may fire.
    min_quality: str = ""
    #: Free-form parameters passed to the logic check through the hit context.
    params: dict[str, Any] = Field(default_factory=dict)

    @field_validator("severity", mode="before")
    @classmethod
    def _coerce_severity(cls, value: Any) -> Any:
        return value if isinstance(value, Severity) else Severity.coerce(str(value))

    @field_validator("confidence", mode="before")
    @classmethod
    def _coerce_confidence(cls, value: Any) -> Any:
        return value if isinstance(value, Confidence) else Confidence.coerce(str(value))

    @field_validator("category", mode="before")
    @classmethod
    def _lower_category(cls, value: Any) -> Any:
        return str(value).lower()

    def reference(self) -> RuleReference:
        """The :class:`RuleReference` attached to every finding this rule makes."""
        return RuleReference(
            rule_id=self.rule_id,
            title=self.title,
            category=self.category,
            source=self.source,
            version=self.tool_version,
            references=list(self.references),
        )

    def summary(self) -> str:
        """One-line description for ``dnscope rules list``."""
        return f"{self.rule_id:32} {self.severity.value:9} {self.confidence.value:7} {self.title}"


class RuleLoadResult(SchemaVersioned):
    """Outcome of loading a rule set (surfaced by ``dnscope rules``)."""

    rules: list[RuleSpec] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    #: Rule ids that were skipped because their logic check is not registered.
    unknown_logic: list[str] = Field(default_factory=list)
    duplicates: list[str] = Field(default_factory=list)

    @property
    def count(self) -> int:
        """Number of usable rules."""
        return len(self.rules)

    def by_category(self) -> dict[str, int]:
        """Rule counts per category."""
        counts: dict[str, int] = {}
        for rule in self.rules:
            counts[rule.category] = counts.get(rule.category, 0) + 1
        return dict(sorted(counts.items()))

    def summary(self) -> str:
        """One-line human summary."""
        text = f"{self.count} rule(s) from {len(self.files)} rule file(s)"
        if self.unknown_logic:
            text += f"; {len(self.unknown_logic)} skipped (unknown logic)"
        if self.errors:
            text += f"; {len(self.errors)} error(s)"
        return text


class RuleEngine:
    """Loads rules and evaluates them against a :class:`ScanContext`."""

    def __init__(
        self,
        rules: Sequence[RuleSpec] = (),
        *,
        workspace: str = "default",
        disabled: Sequence[str] = (),
        only: Sequence[str] = (),
        suppressed: Iterable[str] = (),
    ) -> None:
        self.workspace = workspace
        self.disabled = {str(item) for item in disabled}
        self.only = {str(item) for item in only}
        self.suppressed = {str(item) for item in suppressed}
        self.rules: list[RuleSpec] = list(rules)
        #: Rules skipped at evaluation time, with the reason (for the report).
        self.skipped: dict[str, str] = {}

    # ------------------------------------------------------------------ loading

    @classmethod
    def load(
        cls,
        directories: Sequence[str | Path] = (),
        *,
        include_builtin: bool = True,
        workspace: str = "default",
        disabled: Sequence[str] = (),
        only: Sequence[str] = (),
        suppressed: Iterable[str] = (),
    ) -> tuple[RuleEngine, RuleLoadResult]:
        """Load built-in and custom rule packs.

        Later directories win: a custom rule with the same id replaces the
        built-in, which is how an operator overrides severity without forking.
        """
        result = RuleLoadResult()
        paths: list[Path] = []
        if include_builtin:
            paths.append(BUILTIN_RULES_DIR)
        for directory in directories:
            paths.append(Path(directory).expanduser())

        specs: dict[str, RuleSpec] = {}
        for directory in paths:
            if not directory.is_dir():
                if str(directory) != str(BUILTIN_RULES_DIR):
                    result.errors.append(f"rule directory not found: {directory}")
                continue
            for path in sorted(directory.glob("*.yaml")) + sorted(directory.glob("*.yml")):
                result.files.append(str(path))
                for spec in cls._load_yaml(path, result):
                    if spec.rule_id in specs:
                        result.duplicates.append(spec.rule_id)
                    specs[spec.rule_id] = spec
            for path in sorted(directory.glob("*.py")):
                result.files.append(str(path))
                cls._load_python(path, result)

        for rule_id, spec in specs.items():
            if get_logic(spec.logic) is None:
                result.unknown_logic.append(rule_id)
                continue
            result.rules.append(spec)
        result.rules.sort(key=lambda item: (item.category, item.rule_id))
        engine = cls(
            result.rules,
            workspace=workspace,
            disabled=disabled,
            only=only,
            suppressed=suppressed,
        )
        return engine, result

    @classmethod
    def _load_yaml(cls, path: Path, result: RuleLoadResult) -> list[RuleSpec]:
        """Parse one YAML rule pack."""
        import yaml

        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            result.errors.append(f"{path.name}: {exc}")
            return []
        if not isinstance(document, dict):
            result.errors.append(f"{path.name}: expected a mapping at the top level")
            return []
        entries = document.get("rules")
        if not isinstance(entries, list):
            result.errors.append(f"{path.name}: missing a 'rules' list")
            return []
        default_category = str(document.get("category") or path.stem).lower()
        specs: list[RuleSpec] = []
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                result.errors.append(f"{path.name}[{index}]: rule must be a mapping")
                continue
            try:
                spec = RuleSpec(
                    rule_id=str(entry.get("id") or entry.get("rule_id") or ""),
                    title=str(entry.get("title") or ""),
                    logic=str(entry.get("logic") or ""),
                    severity=str(entry.get("severity") or "LOW"),
                    confidence=str(entry.get("confidence") or "MEDIUM"),
                    description=str(entry.get("description") or ""),
                    recommendation=str(entry.get("recommendation") or ""),
                    category=str(entry.get("category") or default_category),
                    references=[str(item) for item in entry.get("references") or []],
                    tags=[str(item) for item in entry.get("tags") or []],
                    enabled=bool(entry.get("enabled", True)),
                    source="builtin" if path.parent == BUILTIN_RULES_DIR else "custom",
                    path=str(path),
                    match=[str(item) for item in entry.get("match") or []],
                    min_quality=str(entry.get("min_quality") or ""),
                    params=dict(entry.get("params") or {}),
                )
            except (TypeError, ValueError) as exc:
                result.errors.append(f"{path.name}[{index}]: {exc}")
                continue
            missing = [
                field
                for field, value in (
                    ("id", spec.rule_id),
                    ("title", spec.title),
                    ("logic", spec.logic),
                    ("description", spec.description),
                    ("recommendation", spec.recommendation),
                )
                if not value
            ]
            if missing:
                result.errors.append(f"{path.name}[{index}]: missing {', '.join(missing)}")
                continue
            specs.append(spec)
        return specs

    @classmethod
    def _load_python(cls, path: Path, result: RuleLoadResult) -> None:
        """Import a custom Python rule module.

        The module is expected to call
        :func:`dnscope.rules.logic.register_logic` at import time. Loading Python
        means executing code, which is why plugins and custom rules are opt-in and
        the CLI warns about it.
        """
        module_name = f"dnscope_custom_rules_{path.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                result.errors.append(f"{path.name}: could not build an import spec")
                return
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
        except Exception as exc:
            result.errors.append(f"{path.name}: {type(exc).__name__}: {exc}")
            _log.warning("custom rule module %s failed to load: %s", path.name, exc)
            return
        exported = getattr(module, "RULES", None)
        if isinstance(exported, (list, tuple)):
            for entry in exported:
                try:
                    spec_model = RuleSpec.model_validate(dict(entry)) if isinstance(entry, dict) else entry
                except (TypeError, ValueError) as exc:
                    result.errors.append(f"{path.name}: invalid rule entry: {exc}")
                    continue
                if isinstance(spec_model, RuleSpec):
                    spec_model.source = "plugin"
                    spec_model.path = str(path)
                    result.rules.append(spec_model)

    # ------------------------------------------------------------- evaluation

    def applicable(self) -> list[RuleSpec]:
        """Rules that will run (enabled, not disabled, matching any ``only`` filter)."""
        selected: list[RuleSpec] = []
        for rule in self.rules:
            if not rule.enabled:
                self.skipped[rule.rule_id] = "disabled in the rule definition"
                continue
            if rule.rule_id in self.disabled:
                self.skipped[rule.rule_id] = "disabled by --disable-rule"
                continue
            if self.only and rule.rule_id not in self.only and rule.category not in self.only:
                self.skipped[rule.rule_id] = "not selected by --rule"
                continue
            if rule.rule_id in self.suppressed:
                self.skipped[rule.rule_id] = "suppressed by policy"
                continue
            selected.append(rule)
        return selected

    def evaluate(self, context: ScanContext) -> list[Finding]:
        """Run every applicable rule and return validated findings."""
        findings: list[Finding] = []
        seen: set[str] = set()
        for rule in self.applicable():
            check = get_logic(rule.logic)
            if check is None:
                self.skipped[rule.rule_id] = f"logic check '{rule.logic}' is not registered"
                continue
            try:
                hits = check(context)
            except Exception as exc:
                self.skipped[rule.rule_id] = f"{type(exc).__name__}: {exc}"
                _log.warning("rule %s raised: %s", rule.rule_id, exc)
                continue
            if not hits:
                continue
            for hit in hits:
                finding = self._finding(rule, hit, context)
                if finding is None:
                    continue
                key = finding.fingerprint()
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)
        findings.sort(key=lambda item: (-item.severity.rank, -item.confidence.rank, item.rule.rule_id))
        return findings

    # ---------------------------------------------------------------- internals

    def _finding(self, rule: RuleSpec, hit: RuleHit, context: ScanContext) -> Finding | None:
        """Build and validate one finding."""
        if not hit.has_evidence:
            self.skipped.setdefault(rule.rule_id, "hit produced no evidence; finding dropped")
            _log.debug("rule %s produced a hit without evidence for %s", rule.rule_id, hit.target)
            return None
        if rule.match:
            observation = str(hit.location.get("observation", ""))
            if observation and observation not in rule.match:
                return None
        if rule.min_quality and not self._quality_ok(hit, rule.min_quality):
            return None

        severity = Severity.coerce(hit.severity or rule.severity.value)
        confidence = Confidence.coerce(hit.confidence or rule.confidence.value)
        finding = Finding(
            finding_id=new_id("f"),
            rule=rule.reference(),
            title=hit.title or rule.title,
            severity=severity,
            confidence=confidence,
            description=hit.description or rule.description,
            target=hit.target or context.target,
            workspace=self.workspace,
            category=rule.category,
            location=dict(hit.location),
            evidence=list(hit.evidence),
            recommendation=rule.recommendation,
            references=list(rule.references),
            needs_verification=hit.needs_verification,
            analysis_type="RULE_BASED",
            first_seen=utc_now_iso(),
            context={
                **hit.context,
                **rule.params,
                "resolver": context.resolver,
                "transport": context.transport,
                "profile": context.profile,
            },
        )
        problems = finding.validate()
        if problems:
            self.skipped.setdefault(rule.rule_id, "; ".join(problems))
            _log.debug("rule %s produced an invalid finding: %s", rule.rule_id, problems)
            return None
        return finding

    def _quality_ok(self, hit: RuleHit, minimum: str) -> bool:
        """``True`` when at least one evidence entry meets the quality floor."""
        order = ("HEURISTIC", "CORRELATED", "INFERRED", "OBSERVED")
        try:
            threshold = order.index(str(minimum).upper())
        except ValueError:
            return True
        for item in hit.evidence:
            quality = str(getattr(item.source, "quality", "")).upper()
            if quality in order and order.index(quality) >= threshold:
                return True
        return False

    # ----------------------------------------------------------------- helpers

    def describe(self) -> dict[str, Any]:
        """Rule inventory for ``dnscope rules list`` and ``--json`` output."""
        return {
            "total": len(self.rules),
            "applicable": len(self.applicable()),
            "categories": self._category_counts(),
            "severities": self._severity_counts(),
            "skipped": dict(self.skipped),
            "registered_logic": registered_logic(),
            "rules": [
                {
                    "rule_id": rule.rule_id,
                    "title": rule.title,
                    "logic": rule.logic,
                    "severity": rule.severity.value,
                    "confidence": rule.confidence.value,
                    "category": rule.category,
                    "source": rule.source,
                    "enabled": rule.enabled,
                    "description": rule.description,
                    "recommendation": rule.recommendation,
                    "references": rule.references,
                    "tags": rule.tags,
                }
                for rule in self.rules
            ],
        }

    def _category_counts(self) -> dict[str, int]:
        """Rule counts per category."""
        counts: dict[str, int] = {}
        for rule in self.rules:
            counts[rule.category] = counts.get(rule.category, 0) + 1
        return dict(sorted(counts.items()))

    def _severity_counts(self) -> dict[str, int]:
        """Rule counts per severity."""
        counts: dict[str, int] = {}
        for rule in self.rules:
            counts[rule.severity.value] = counts.get(rule.severity.value, 0) + 1
        return counts

    def find(self, rule_id: str) -> RuleSpec | None:
        """Look up one rule by id."""
        return next((rule for rule in self.rules if rule.rule_id == rule_id), None)

    def validate_all(self) -> list[str]:
        """Return every problem with the loaded rule set."""
        problems: list[str] = []
        for rule in self.rules:
            if get_logic(rule.logic) is None:
                problems.append(f"{rule.rule_id}: logic check '{rule.logic}' is not registered")
            if not rule.description:
                problems.append(f"{rule.rule_id}: missing description")
            if not rule.recommendation:
                problems.append(f"{rule.rule_id}: missing recommendation")
            if rule.category not in CATEGORIES:
                problems.append(f"{rule.rule_id}: unknown category '{rule.category}'")
        return problems


def default_engine(
    *,
    extra_directories: Sequence[str | Path] = (),
    workspace: str = "default",
    disabled: Sequence[str] = (),
    only: Sequence[str] = (),
    suppressed: Iterable[str] = (),
) -> RuleEngine:
    """Build the engine with the built-in packs plus any custom directories."""
    engine, result = RuleEngine.load(
        extra_directories,
        workspace=workspace,
        disabled=disabled,
        only=only,
        suppressed=suppressed,
    )
    if result.errors:
        _log.warning("rule loading reported %d problem(s): %s", len(result.errors), result.errors[:5])
    if result.unknown_logic:
        raise RuleError(
            f"{len(result.unknown_logic)} rule(s) reference an unknown logic check: "
            f"{', '.join(result.unknown_logic[:5])}"
        )
    return engine


__all__ = [
    "BUILTIN_RULES_DIR",
    "CATEGORIES",
    "RuleEngine",
    "RuleLoadResult",
    "RuleSpec",
    "default_engine",
]
