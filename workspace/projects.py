from __future__ import annotations

import re
import shutil
import sqlite3
import uuid
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from core.config import DB_PATH
from core.db import connect

_PROJECT_ID = re.compile(r"^[a-f0-9]{32}$")
_MAX_NAME = 100
_MAX_DESCRIPTION = 2000


@dataclass(frozen=True)
class WorkspaceProject:
    project_id: str
    owner_id: int
    name: str
    description: str
    root_path: Path
    location_kind: str
    is_default: bool
    archived: bool
    created_at: str
    updated_at: str

    def public(self, *, mission_count: int | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {
            "project_id": self.project_id,
            "name": self.name,
            "description": self.description,
            "location_kind": getattr(self, "location_kind", "managed"),
            "is_default": self.is_default,
            "archived": self.archived,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
        if mission_count is not None:
            result["mission_count"] = int(mission_count)
        return result


class WorkspaceProjectStore:
    """Owner-scoped project metadata and directories, backed by the app state DB."""

    def __init__(self, *, root_base: str | Path | None = None):
        self.root_base = Path(root_base or DB_PATH.parent / "workspaces").expanduser().resolve()
        self.root_base.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _name(value: object) -> str:
        name = str(value or "").strip()
        if not name or len(name) > _MAX_NAME or any(ord(char) < 32 for char in name):
            raise ValueError("invalid_project_name")
        return name

    @staticmethod
    def _description(value: object) -> str:
        description = str(value or "").strip()
        if len(description) > _MAX_DESCRIPTION or any(ord(char) < 32 and char not in "\n\t" for char in description):
            raise ValueError("invalid_project_description")
        return description

    @staticmethod
    def _from_row(row) -> WorkspaceProject:
        return WorkspaceProject(
            project_id=str(row["project_id"]),
            owner_id=int(row["owner_id"]),
            name=str(row["name"]),
            description=str(row["description"] or ""),
            root_path=Path(str(row["root_path"])).expanduser().resolve(),
            location_kind=str(row["location_kind"] or "managed"),
            is_default=bool(row["is_default"]),
            archived=bool(row["archived"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
        )

    def _project_root(self, project_id: str) -> Path:
        if not _PROJECT_ID.fullmatch(project_id):
            raise ValueError("invalid_project_id")
        path = (self.root_base / project_id).resolve()
        if path.parent != self.root_base:
            raise ValueError("invalid_project_path")
        return path

    def _get(self, owner_id: int, project_id: str) -> WorkspaceProject | None:
        if owner_id <= 0 or not _PROJECT_ID.fullmatch(str(project_id)):
            return None
        with connect() as con:
            row = con.execute(
                "SELECT * FROM workspace_projects WHERE owner_id=? AND project_id=?",
                (int(owner_id), str(project_id)),
            ).fetchone()
        return self._from_row(row) if row else None

    def get(self, owner_id: int, project_id: str, *, include_archived: bool = True) -> WorkspaceProject:
        project = self._get(owner_id, project_id)
        if project is None or (project.archived and not include_archived):
            raise KeyError("unknown_project")
        return project

    def ensure_default(self, owner_id: int) -> WorkspaceProject:
        if isinstance(owner_id, bool) or int(owner_id) <= 0:
            raise ValueError("invalid_owner_id")
        owner_id = int(owner_id)
        with connect() as con:
            row = con.execute(
                "SELECT * FROM workspace_projects WHERE owner_id=? AND is_default=1",
                (owner_id,),
            ).fetchone()
            if row:
                project = self._from_row(row)
                project.root_path.mkdir(parents=True, exist_ok=True)
                return project

        project_id = uuid.uuid4().hex
        root_path = self._project_root(project_id)
        root_path.mkdir(parents=True, exist_ok=False)
        try:
            with connect() as con:
                con.execute(
                    "INSERT INTO workspace_projects(project_id,owner_id,name,description,root_path,is_default) "
                    "VALUES(?,?,?,?,?,1)",
                    (project_id, owner_id, "General", "Default owner workspace", str(root_path)),
                )
                con.commit()
        except sqlite3.IntegrityError:
            shutil.rmtree(root_path, ignore_errors=True)
            with connect() as con:
                row = con.execute(
                    "SELECT * FROM workspace_projects WHERE owner_id=? AND is_default=1",
                    (owner_id,),
                ).fetchone()
            if row is None:
                raise
            project = self._from_row(row)
            project.root_path.mkdir(parents=True, exist_ok=True)
            return project
        return self.get(owner_id, project_id)

    def create(self, owner_id: int, name: object, description: object = "", *, selected_root: str | Path | None = None) -> WorkspaceProject:
        if isinstance(owner_id, bool) or int(owner_id) <= 0:
            raise ValueError("invalid_owner_id")
        owner_id = int(owner_id)
        safe_name = self._name(name)
        safe_description = self._description(description)
        project_id = uuid.uuid4().hex
        managed_root = selected_root is None
        if managed_root:
            root_path = self._project_root(project_id)
            root_path.mkdir(parents=True, exist_ok=False)
            location_kind = "managed"
        else:
            selected = Path(selected_root).expanduser()
            if selected.is_symlink():
                raise ValueError("project_folder_symlink_not_allowed")
            try:
                root_path = selected.resolve(strict=True)
            except OSError as exc:
                raise ValueError("project_folder_not_found") from exc
            if not root_path.is_dir() or len(root_path.parts) < 3:
                raise ValueError("project_folder_must_be_a_specific_directory")
            if os.name == "nt" and str(root_path).startswith("\\\\"):
                raise ValueError("network_project_folder_not_supported")
            root_text = os.path.normcase(str(root_path))
            base_text = os.path.normcase(str(self.root_base))
            if (
                root_text == base_text
                or root_text.startswith(base_text.rstrip(os.sep) + os.sep)
                or base_text.startswith(root_text.rstrip(os.sep) + os.sep)
            ):
                raise ValueError("project_folder_overlaps_application_data")
            root_path = Path(root_text)
            location_kind = "selected-folder"
        try:
            with connect() as con:
                con.execute(
                    "INSERT INTO workspace_projects(project_id,owner_id,name,description,root_path,location_kind) "
                    "VALUES(?,?,?,?,?,?)",
                    (project_id, owner_id, safe_name, safe_description, str(root_path), location_kind),
                )
                con.commit()
        except sqlite3.IntegrityError as exc:
            if managed_root:
                shutil.rmtree(root_path, ignore_errors=True)
            error = "project_folder_already_registered" if "root_path" in str(exc) else "project_name_already_exists"
            raise ValueError(error) from exc
        return self.get(owner_id, project_id)

    def list(self, owner_id: int, *, include_archived: bool = True) -> list[dict[str, Any]]:
        if owner_id <= 0:
            raise ValueError("invalid_owner_id")
        where = "owner_id=?" + ("" if include_archived else " AND archived=0")
        with connect() as con:
            rows = con.execute(
                "SELECT p.*, (SELECT COUNT(*) FROM mission_projects m "
                "WHERE m.owner_id=p.owner_id AND m.project_id=p.project_id) AS mission_count "
                f"FROM workspace_projects p WHERE {where} ORDER BY p.is_default DESC, p.archived, p.name COLLATE NOCASE",
                (int(owner_id),),
            ).fetchall()
        return [self._from_row(row).public(mission_count=int(row["mission_count"])) for row in rows]

    def update(self, owner_id: int, project_id: str, *, name: object | None = None, description: object | None = None, archived: object | None = None) -> WorkspaceProject:
        project = self.get(owner_id, project_id)
        updates: dict[str, object] = {}
        if name is not None:
            updates["name"] = self._name(name)
        if description is not None:
            updates["description"] = self._description(description)
        if archived is not None:
            if not isinstance(archived, bool):
                raise ValueError("invalid_archive_state")
            if project.is_default and archived:
                raise ValueError("default_project_cannot_be_archived")
            updates["archived"] = int(archived)
        if not updates:
            return project
        updates["updated_at"] = "CURRENT_TIMESTAMP"
        assignments = []
        values: list[object] = []
        for key, value in updates.items():
            if key == "updated_at":
                assignments.append("updated_at=CURRENT_TIMESTAMP")
            else:
                assignments.append(f"{key}=?")
                values.append(value)
        values.extend([int(owner_id), str(project_id)])
        try:
            with connect() as con:
                con.execute(
                    f"UPDATE workspace_projects SET {', '.join(assignments)} WHERE owner_id=? AND project_id=?",
                    values,
                )
                con.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError("project_name_already_exists") from exc
        return self.get(owner_id, project_id)

    def assign_mission(self, owner_id: int, mission_id: str, project_id: str) -> None:
        if owner_id <= 0 or not mission_id or len(str(mission_id)) > 128:
            raise ValueError("invalid_mission_assignment")
        project = self.get(owner_id, project_id, include_archived=False)
        with connect() as con:
            current = con.execute(
                "SELECT owner_id FROM mission_projects WHERE mission_id=?",
                (str(mission_id),),
            ).fetchone()
            if current and int(current["owner_id"]) != int(owner_id):
                raise PermissionError("mission_project_owner_mismatch")
            con.execute(
                "INSERT INTO mission_projects(mission_id,owner_id,project_id) VALUES(?,?,?) "
                "ON CONFLICT(mission_id) DO UPDATE SET project_id=excluded.project_id "
                "WHERE mission_projects.owner_id=excluded.owner_id",
                (str(mission_id), int(owner_id), project.project_id),
            )
            con.commit()

    def project_for_mission(self, owner_id: int, mission_id: str) -> str:
        with connect() as con:
            row = con.execute(
                "SELECT project_id FROM mission_projects WHERE owner_id=? AND mission_id=?",
                (int(owner_id), str(mission_id)),
            ).fetchone()
        return str(row["project_id"]) if row else ""

    def map_missions(self, owner_id: int, mission_ids: Iterable[str]) -> dict[str, str]:
        ids = [str(item) for item in mission_ids if item]
        if not ids:
            return {}
        placeholders = ",".join("?" for _ in ids)
        with connect() as con:
            rows = con.execute(
                f"SELECT mission_id, project_id FROM mission_projects WHERE owner_id=? AND mission_id IN ({placeholders})",
                (int(owner_id), *ids),
            ).fetchall()
        return {str(row["mission_id"]): str(row["project_id"]) for row in rows}
