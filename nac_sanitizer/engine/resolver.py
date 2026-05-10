"""JSONPath-based path resolution engine."""

from typing import Any

from jsonpath_ng.ext.parser import ExtentedJsonPathParser
from jsonpath_ng.jsonpath import DatumInContext


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
                raise PathResolutionError(
                    f"Invalid JSONPath expression: {path}\n{e}"
                ) from e
        return self._cache[path]

    def find_matches(self, path: str, data: Any) -> list[DatumInContext]:
        """Find all values matching a JSONPath expression in the given data."""
        expr = self.parse(path)
        return expr.find(data)

    def update_value(self, match: DatumInContext, data: Any, new_value: Any) -> Any:
        """Replace the value at a matched path location in-place."""
        match.full_path.update_or_create(data, new_value)
        return data
