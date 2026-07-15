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
                parent[match.path.indices[0]] = new_value
            else:
                match.full_path.update_or_create(data, new_value)
        else:
            match.full_path.update_or_create(data, new_value)
        return data
