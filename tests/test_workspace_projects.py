from __future__ import annotations

from pathlib import Path

import pytest

import core.db as db
from workspace.projects import WorkspaceProjectStore


@pytest.fixture
def project_store(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "state" / "test.sqlite3")
    for owner_id, username in ((1, "owner-one"), (2, "owner-two")):
        with db.connect() as con:
            con.execute(
                "INSERT INTO owner_accounts(owner_id,username,password_hash,kdf_algorithm,kdf_params_json) "
                "VALUES(?,?,?,?,?)",
                (owner_id, username, "test-hash", "test", "{}"),
            )
            con.commit()
    return WorkspaceProjectStore(root_base=tmp_path / "private" / "workspaces"), tmp_path


def test_projects_are_owner_scoped_and_default_cannot_be_archived(project_store):
    store, _tmp_path = project_store
    default = store.ensure_default(1)
    project = store.create(1, "Incident Response", "Owner-controlled local work")
    store.ensure_default(2)

    assert default.is_default is True
    assert default.root_path.is_dir()
    assert store.get(1, project.project_id).name == "Incident Response"
    with pytest.raises(KeyError, match="unknown_project"):
        store.get(2, project.project_id)
    with pytest.raises(ValueError, match="default_project_cannot_be_archived"):
        store.update(1, default.project_id, archived=True)
    assert all("root_path" not in item for item in store.list(1))


def test_mission_assignment_stays_bound_to_owner_and_active_project(project_store):
    store, _tmp_path = project_store
    project = store.create(1, "Blue Team")
    store.assign_mission(1, "mission-owner-one", project.project_id)
    assert store.project_for_mission(1, "mission-owner-one") == project.project_id
    assert store.map_missions(1, ["mission-owner-one", "missing"]) == {
        "mission-owner-one": project.project_id
    }
    with pytest.raises(PermissionError, match="mission_project_owner_mismatch"):
        store.assign_mission(2, "mission-owner-one", store.ensure_default(2).project_id)

    store.update(1, project.project_id, archived=True)
    with pytest.raises(KeyError, match="unknown_project"):
        store.assign_mission(1, "mission-two", project.project_id)
    store.update(1, project.project_id, archived=False)
    store.assign_mission(1, "mission-two", project.project_id)


def test_imported_folder_is_canonical_local_and_unique_per_owner(project_store, tmp_path):
    store, _ = project_store
    selected = tmp_path / "picked project"
    selected.mkdir()
    project = store.create(1, "Imported", "Selected by native picker", selected_root=selected)
    assert project.location_kind == "selected-folder"
    assert project.root_path == selected.resolve()
    assert project.public()["location_kind"] == "selected-folder"
    assert "root_path" not in project.public()
    with pytest.raises(ValueError, match="project_folder_already_registered"):
        store.create(1, "Duplicate root", selected_root=selected)
    with pytest.raises(KeyError, match="unknown_project"):
        store.get(2, project.project_id)


def test_project_store_rejects_non_specific_and_application_data_paths(project_store, tmp_path):
    store, _ = project_store
    with pytest.raises(ValueError, match="project_folder_must_be_a_specific_directory"):
        store.create(1, "Filesystem root", selected_root=Path("/"))
    store.root_base.mkdir(parents=True, exist_ok=True)
    with pytest.raises(ValueError, match="project_folder_overlaps_application_data"):
        store.create(1, "Application data", selected_root=store.root_base)
    child = store.root_base / "child"
    child.mkdir()
    with pytest.raises(ValueError, match="project_folder_overlaps_application_data"):
        store.create(1, "Nested app data", selected_root=child)


def test_project_validation_and_archive_state_are_explicit(project_store):
    store, _ = project_store
    with pytest.raises(ValueError, match="invalid_project_name"):
        store.create(1, "\x00")
    project = store.create(1, "Project")
    with pytest.raises(ValueError, match="invalid_archive_state"):
        store.update(1, project.project_id, archived="true")
    with pytest.raises(KeyError, match="unknown_project"):
        store.get(1, "../escape")
