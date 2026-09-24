# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""JSONPath-based path resolution engine."""

import logging
from typing import Any

from jsonpath_ng.ext.parser import ExtentedJsonPathParser
from jsonpath_ng.jsonpath import DatumInContext, Fields, Index

logger = logging.getLogger(__name__)


class PathResolutionError(Exception):
    """Raised when a JSONPath expression cannot be parsed."""


class PathResolver:
    """Resolves JSONPath expressions against JSON data and supports in-place updates."""

    def __init__(self) -> None:
        self._parser = ExtentedJsonPathParser()
        self._cache: dict[str, Any] = {}

    def parse(self, path: str) -> Any:
        """Parse a JSONPath expression, returning a cached compiled expression."""
        if path not in self._cache:
            try:
                self._cache[path] = self._parser.parse(path)
            except Exception as e:
                logger.warning("Invalid JSONPath expression: %s", path)
                raise PathResolutionError(
                    f"Invalid JSONPath expression: {path}\n{e}"
                ) from e
            logger.debug("Compiled JSONPath: %s", path)
        return self._cache[path]

    def find_matches(self, path: str, data: Any) -> list[DatumInContext]:
        """Find all values matching a JSONPath expression in the given data."""
        expr = self.parse(path)
        return expr.find(data)

    def update_value(self, match: DatumInContext, data: Any, new_value: Any) -> Any:
        """Replace the value at a matched path location in-place.

        Uses direct parent-container mutation for O(1) updates instead of
        jsonpath_ng's update_or_create which re-walks the entire document.
        """
        if match.context is not None:
            parent = match.context.value
            if isinstance(match.path, Fields):
                for field in match.path.fields:
                    parent[field] = new_value
            elif isinstance(match.path, Index) and len(match.path.indices) == 1:
                if _is_coerced(match.context):
                    # The parent list was synthesized by a [*] slice around a
                    # non-list node; replace that node in the real document.
                    self.update_value(
                        _outermost_coerced(match.context), data, new_value
                    )
                else:
                    parent[match.path.indices[0]] = new_value
            else:
                match.full_path.update_or_create(data, new_value)
        else:
            match.full_path.update_or_create(data, new_value)
        return data


_MISSING = object()


def _is_coerced(node: DatumInContext) -> bool:
    """Return True if ``node`` holds a list jsonpath_ng synthesized, not real data.

    ``Slice.find`` wraps a non-list value as ``DatumInContext([value],
    path=original.path, context=original.context)``. The wrapper keeps the
    real node's location, so resolving that location in its parent yields an
    object that is *not* the wrapper's list. A real list always resolves to
    itself, so this identity check never misfires on genuine list data.
    """
    if node.context is None or not isinstance(node.value, list):
        return False
    actual = _resolve_child(node.context.value, node.path)
    return actual is not _MISSING and actual is not node.value


def _outermost_coerced(node: DatumInContext) -> DatumInContext:
    """Climb nested coerced wrappers (``[*][*]`` over a scalar) to the outermost.

    Each nested wrapper points at the one produced by the previous slice, so
    only the outermost wrapper's ``context``/``path`` address the real node.
    Treating that wrapper as a match makes ``update_value`` replace the node.
    """
    parent = node.context
    while parent is not None and _is_coerced(parent):
        node = parent
        parent = node.context
    return node


def _resolve_child(container: Any, path: Any) -> Any:
    """Look up a single-step ``Fields``/``Index`` path in ``container``.

    Returns ``_MISSING`` when the path is not a single-step lookup or the key
    is absent, so callers keep the pre-existing (uncoerced) behavior rather
    than guessing.
    """
    try:
        if isinstance(path, Fields) and len(path.fields) == 1:
            return container[path.fields[0]]
        if isinstance(path, Index) and len(path.indices) == 1:
            return container[path.indices[0]]
    except (KeyError, IndexError, TypeError):
        return _MISSING
    return _MISSING
