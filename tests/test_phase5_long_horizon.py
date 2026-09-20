"""
CyberSentinel X - Phase 5: Long-Horizon Conversational Agent Tests

Comprehensive tests for Phase 5A, 5B, 5C, 5D, 5E, 5F, 5G, 5H
"""

import json
import os
import tempfile
import pytest
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

# =============================================================================
# Phase 5A: Runtime Limits Tests
# =============================================================================

class TestPhase5A_RuntimeLimits:
    """Test RuntimeLimits loading from Owner Policy."""
    
    def test_runtime_limits_load_from_policy(self):
        """Test that RuntimeLimits loads from Owner Policy."""
        from agent.context import RuntimeLimits
        from security.owner_policy import get_runtime_limits
        
        # Get limits from policy
        limits_config = get_runtime_limits()
        
        # Verify all limits are present
        assert hasattr(limits_config, 'max_context_messages')
        assert hasattr(limits_config, 'max_context_chars')
        assert hasattr(limits_config, 'max_result_chars')
        assert hasattr(limits_config, 'max_tool_calls')
        assert hasattr(limits_config, 'max_execution_steps')
        assert hasattr(limits_config, 'max_same_tool_calls')
        assert hasattr(limits_config, 'max_execution_time_seconds')
        assert hasattr(limits_config, 'max_pending_tasks')
        assert hasattr(limits_config, 'max_retries')
        assert hasattr(limits_config, 'max_total_output_chars')
        
        # Verify values match policy
        assert limits_config.max_execution_steps == 20
        assert limits_config.max_same_tool_calls == 5
        assert limits_config.max_execution_time_seconds == 300
        
    def test_runtime_limits_from_owner_policy(self):
        """Test RuntimeLimits.from_owner_policy() loads actual policy."""
        from agent.context import RuntimeLimits
        
        limits = RuntimeLimits.from_owner_policy()
        
        # Verify all limits are loaded
        assert limits.max_context_messages == 50
        assert limits.max_context_chars == 32000
        assert limits.max_result_chars == 4000
        assert limits.max_tool_calls == 10
        assert limits.max_execution_steps == 20
        assert limits.max_same_tool_calls == 5
        assert limits.max_execution_time_seconds == 300
        assert limits.max_pending_tasks == 10
        assert limits.max_retries == 3
        assert limits.max_total_output_chars == 8000
    
    def test_agent_loop_uses_runtime_limits(self):
        """Test that AgentLoop uses RuntimeLimits instead of hard-coded max_steps."""
        from agent.loop import AgentLoop
        from agent.context import RuntimeLimits
        
        # Create AgentLoop with default limits
        loop = AgentLoop(MagicMock(), lambda *args, **kwargs: {})
        
        # Verify max_steps comes from RuntimeLimits
        assert loop.max_steps == 20
        assert loop.runtime_limits.max_execution_steps == 20
    
    def test_agent_loop_custom_runtime_limits(self):
        """Test that AgentLoop can use custom RuntimeLimits."""
        from agent.loop import AgentLoop
        from agent.context import RuntimeLimits
        
        custom_limits = RuntimeLimits(
            max_context_messages=100,
            max_context_chars=64000,
            max_result_chars=8000,
            max_tool_calls=20,
            max_execution_steps=50,
            max_same_tool_calls=10,
            max_execution_time_seconds=600,
            max_pending_tasks=20,
            max_retries=5,
            max_total_output_chars=16000,
        )
        
        loop = AgentLoop(MagicMock(), lambda *args, **kwargs: {}, runtime_limits=custom_limits)
        
        assert loop.max_steps == 50
        assert loop.runtime_limits.max_execution_steps == 50


# =============================================================================
# Phase 5B: Task Management Tests
# =============================================================================

class TestPhase5B_TaskManagement:
    """Test Task, TaskManager, and State management."""
    
    def setup_method(self):
        """Set up test database."""
        # Use in-memory database for tests
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.sqlite3', delete=False)
        self.temp_db.close()
        
        # Patch database path
        self.db_patch = patch('agent.task_manager.DB_PATH', Path(self.temp_db.name))
        self.db_patch.start()
        
        # Re-initialize database
        from agent.task_manager import _init_db
        _init_db()
    
    def teardown_method(self):
        """Clean up test database."""
        self.db_patch.stop()
        try:
            os.unlink(self.temp_db.name)
        except FileNotFoundError:
            pass
    
    def test_task_creation(self):
        """Test Task creation."""
        from agent.task import Task, TaskStatus
        
        task = Task.create(
            conversation_id="conv-1",
            request_id="req-1",
            owner_session_id="session-1",
            objective="Test objective",
            provider="test-provider",
            model="test-model",
        )
        
        assert task.task_id is not None
        assert len(task.task_id) == 32  # UUID hex
        assert task.conversation_id == "conv-1"
        assert task.request_id == "req-1"
        assert task.owner_session_id == "session-1"
        assert task.status == TaskStatus.QUEUED
        assert task.objective == "Test objective"
        assert task.current_step == 0
        assert task.retry_count == 0
        assert task.tool_calls == []
        assert task.created_at is not None
        assert task.updated_at is not None
    
    def test_task_status_updates(self):
        """Test Task status updates."""
        from agent.task import Task, TaskStatus
        
        task = Task.create(
            conversation_id="conv-1",
            request_id="req-1",
            owner_session_id="session-1",
            objective="Test",
        )
        
        # Test status transitions
        task.update_status(TaskStatus.PLANNING)
        assert task.status == TaskStatus.PLANNING
        assert task.started_at is None
        
        task.update_status(TaskStatus.EXECUTING)
        assert task.status == TaskStatus.EXECUTING
        assert task.started_at is not None
        
        task.update_status(TaskStatus.COMPLETED)
        assert task.status == TaskStatus.COMPLETED
        assert task.finished_at is not None
    
    def test_task_tool_calls(self):
        """Test Task tool call recording."""
        from agent.task import Task
        
        task = Task.create(
            conversation_id="conv-1",
            request_id="req-1",
            owner_session_id="session-1",
            objective="Test",
        )
        
        task.add_tool_call("search", "completed", "req-search-1")
        assert len(task.tool_calls) == 1
        assert task.tool_calls[0]["tool_name"] == "search"
        assert task.tool_calls[0]["status"] == "completed"
        assert task.tool_calls[0]["request_id"] == "req-search-1"
        assert "tool_call_id" in task.tool_calls[0]
    
    def test_task_step_increment(self):
        """Test Task step incrementing."""
        from agent.task import Task
        
        task = Task.create(
            conversation_id="conv-1",
            request_id="req-1",
            owner_session_id="session-1",
            objective="Test",
        )
        
        assert task.current_step == 0
        task.increment_step()
        assert task.current_step == 1
        task.increment_step()
        assert task.current_step == 2
    
    def test_task_retry_increment(self):
        """Test Task retry counting."""
        from agent.task import Task
        
        task = Task.create(
            conversation_id="conv-1",
            request_id="req-1",
            owner_session_id="session-1",
            objective="Test",
        )
        
        assert task.retry_count == 0
        task.increment_retry()
        assert task.retry_count == 1
    
    def test_task_active_states(self):
        """Test Task active state detection."""
        from agent.task import Task, TaskStatus
        
        task = Task.create(
            conversation_id="conv-1",
            request_id="req-1",
            owner_session_id="session-1",
            objective="Test",
        )
        
        # Queued is active
        assert task.is_active
        assert not task.is_terminal
        
        # Execute and check
        task.update_status(TaskStatus.EXECUTING)
        assert task.is_active
        assert not task.is_terminal
        
        # Completed is terminal
        task.update_status(TaskStatus.COMPLETED)
        assert not task.is_active
        assert task.is_terminal
    
    def test_task_serialization(self):
        """Test Task serialization and deserialization."""
        from agent.task import Task, TaskStatus
        
        task = Task.create(
            conversation_id="conv-1",
            request_id="req-1",
            owner_session_id="session-1",
            objective="Test",
        )
        task.update_status(TaskStatus.EXECUTING)
        task.add_tool_call("search", "completed")
        
        # Serialize
        data = task.to_dict()
        assert "task_id" in data
        assert data["status"] == "executing"
        assert len(data["tool_calls"]) == 1
        
        # Deserialize
        restored = Task.from_dict(data)
        assert restored.task_id == task.task_id
        assert restored.status == TaskStatus.EXECUTING
        assert len(restored.tool_calls) == 1
    
    def test_task_manager_create(self):
        """Test TaskManager task creation."""
        from agent.task_manager import TaskManager
        
        task = TaskManager.create_task(
            conversation_id="conv-1",
            request_id="req-1",
            owner_session_id="session-1",
            objective="Test objective",
            provider="test-provider",
            model="test-model",
        )
        
        assert task.task_id is not None
        assert task.objective == "Test objective"
        
        # Verify persistence
        retrieved = TaskManager.get_task(task.task_id)
        assert retrieved is not None
        assert retrieved.task_id == task.task_id
    
    def test_task_manager_update(self):
        """Test TaskManager task updates."""
        from agent.task_manager import TaskManager
        from agent.task import TaskStatus
        
        task = TaskManager.create_task(
            conversation_id="conv-1",
            request_id="req-1",
            owner_session_id="session-1",
            objective="Test",
        )
        
        task.update_status(TaskStatus.EXECUTING)
        task.add_tool_call("search", "completed")
        TaskManager.update_task(task)
        
        # Verify update
        retrieved = TaskManager.get_task(task.task_id)
        assert retrieved.status == TaskStatus.EXECUTING
        assert len(retrieved.tool_calls) == 1
    
    def test_task_manager_delete(self):
        """Test TaskManager task deletion."""
        from agent.task_manager import TaskManager
        
        task = TaskManager.create_task(
            conversation_id="conv-1",
            request_id="req-1",
            owner_session_id="session-1",
            objective="Test",
        )
        
        # Verify exists
        assert TaskManager.get_task(task.task_id) is not None
        
        # Delete
        result = TaskManager.delete_task(task.task_id)
        assert result is True
        
        # Verify deleted
        assert TaskManager.get_task(task.task_id) is None
    
    def test_task_manager_get_by_conversation(self):
        """Test TaskManager get tasks by conversation."""
        from agent.task_manager import TaskManager
        
        # Create multiple tasks for same conversation
        task1 = TaskManager.create_task(
            conversation_id="conv-1",
            request_id="req-1",
            owner_session_id="session-1",
            objective="Test 1",
        )
        task2 = TaskManager.create_task(
            conversation_id="conv-1",
            request_id="req-2",
            owner_session_id="session-1",
            objective="Test 2",
        )
        task3 = TaskManager.create_task(
            conversation_id="conv-2",
            request_id="req-3",
            owner_session_id="session-1",
            objective="Test 3",
        )
        
        # Get tasks for conv-1
        tasks = TaskManager.get_tasks_by_conversation("conv-1")
        assert len(tasks) == 2
        task_ids = {t.task_id for t in tasks}
        assert task1.task_id in task_ids
        assert task2.task_id in task_ids
        assert task3.task_id not in task_ids
    
    def test_task_manager_get_active_tasks(self):
        """Test TaskManager get active tasks."""
        from agent.task_manager import TaskManager
        from agent.task import TaskStatus
        
        # Create active task
        active_task = TaskManager.create_task(
            conversation_id="conv-1",
            request_id="req-1",
            owner_session_id="session-1",
            objective="Active",
        )
        
        # Create completed task
        completed_task = TaskManager.create_task(
            conversation_id="conv-2",
            request_id="req-2",
            owner_session_id="session-1",
            objective="Completed",
        )
        completed_task.update_status(TaskStatus.COMPLETED)
        TaskManager.update_task(completed_task)
        
        # Get active tasks
        active_tasks = TaskManager.get_active_tasks()
        assert len(active_tasks) == 1
        assert active_tasks[0].task_id == active_task.task_id
    
    def test_task_manager_stats(self):
        """Test TaskManager statistics."""
        from agent.task_manager import TaskManager
        from agent.task import TaskStatus
        
        # Create tasks with different statuses
        active = TaskManager.create_task(
            conversation_id="conv-1",
            request_id="req-1",
            owner_session_id="session-1",
            objective="Active",
        )
        
        completed = TaskManager.create_task(
            conversation_id="conv-2",
            request_id="req-2",
            owner_session_id="session-1",
            objective="Completed",
        )
        completed.update_status(TaskStatus.COMPLETED)
        TaskManager.update_task(completed)
        
        failed = TaskManager.create_task(
            conversation_id="conv-3",
            request_id="req-3",
            owner_session_id="session-1",
            objective="Failed",
        )
        failed.update_status(TaskStatus.FAILED)
        TaskManager.update_task(failed)
        
        stats = TaskManager.get_stats()
        assert stats["total"] == 3
        assert stats["active"] == 1
        assert stats["completed"] == 1
        assert stats["failed"] == 1
    
    def test_task_state_snapshot(self):
        """Test TaskState immutable snapshot."""
        from agent.task_manager import TaskManager
        from agent.state import TaskState
        
        task = TaskManager.create_task(
            conversation_id="conv-1",
            request_id="req-1",
            owner_session_id="session-1",
            objective="Test",
            provider="provider-1",
            model="model-1",
        )
        
        state = TaskManager.get_task_state(task.task_id)
        assert state is not None
        assert state.task_id == task.task_id
        assert state.conversation_id == "conv-1"
        assert state.objective == "Test"
        assert state.provider == "provider-1"
        assert state.model == "model-1"


# =============================================================================
# Phase 5C: Conversation Memory Tests
# =============================================================================

class TestPhase5C_ConversationMemory:
    """Test MemoryProvider and ConversationMemory."""
    
    def setup_method(self):
        """Set up test database."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.sqlite3', delete=False)
        self.temp_db.close()
        
        self.db_patch = patch('agent.memory.MEMORY_DB_PATH', Path(self.temp_db.name))
        self.db_patch.start()
        
        from agent.memory import _init_memory_db
        _init_memory_db()
    
    def teardown_method(self):
        """Clean up test database."""
        self.db_patch.stop()
        try:
            os.unlink(self.temp_db.name)
        except FileNotFoundError:
            pass
    
    def test_memory_item_creation(self):
        """Test MemoryItem creation."""
        from agent.memory import MemoryItem, MemoryType, TrustClassification
        
        item = MemoryItem.create(
            conversation_id="conv-1",
            content="Test memory content",
            memory_type=MemoryType.FACT,
            trust_classification=TrustClassification.UNTRUSTED_DATA,
            source="user",
            provenance="user_message",
        )
        
        assert item.memory_id is not None
        assert item.conversation_id == "conv-1"
        assert item.content == "Test memory content"
        assert item.memory_type == MemoryType.FACT
        assert item.trust_classification == TrustClassification.UNTRUSTED_DATA
        assert item.source == "user"
        assert item.provenance == "user_message"
        assert item.content_hash is not None
        assert len(item.content_hash) == 16
    
    def test_memory_item_serialization(self):
        """Test MemoryItem serialization."""
        from agent.memory import MemoryItem, MemoryType, TrustClassification
        
        item = MemoryItem.create(
            conversation_id="conv-1",
            content="Test",
            memory_type=MemoryType.FACT,
            trust_classification=TrustClassification.UNTRUSTED_DATA,
            source="user",
            provenance="user_message",
        )
        
        # Serialize
        data = item.to_dict()
        assert "memory_id" in data
        assert data["memory_type"] == "fact"
        assert data["trust_classification"] == "untrusted_data"
        
        # Deserialize
        restored = MemoryItem.from_dict(data)
        assert restored.memory_id == item.memory_id
        assert restored.memory_type == MemoryType.FACT
        assert restored.trust_classification == TrustClassification.UNTRUSTED_DATA
    
    def test_memory_provider_store(self):
        """Test MemoryProvider store and retrieve."""
        from agent.memory import MemoryProvider, MemoryItem, MemoryType, TrustClassification
        
        item = MemoryItem.create(
            conversation_id="conv-1",
            content="Test memory",
            memory_type=MemoryType.FACT,
            trust_classification=TrustClassification.UNTRUSTED_DATA,
            source="user",
            provenance="user_message",
        )
        
        MemoryProvider.store_memory(item)
        
        # Retrieve
        retrieved = MemoryProvider.get_memory_item(item.memory_id)
        assert retrieved is not None
        assert retrieved.content == "Test memory"
    
    def test_memory_provider_get_by_conversation(self):
        """Test MemoryProvider get memory by conversation."""
        from agent.memory import MemoryProvider, MemoryItem, MemoryType, TrustClassification
        
        item1 = MemoryItem.create(
            conversation_id="conv-1",
            content="Memory 1",
            memory_type=MemoryType.FACT,
            trust_classification=TrustClassification.UNTRUSTED_DATA,
            source="user",
            provenance="user_message",
        )
        item2 = MemoryItem.create(
            conversation_id="conv-1",
            content="Memory 2",
            memory_type=MemoryType.DECISION,
            trust_classification=TrustClassification.UNTRUSTED_DATA,
            source="user",
            provenance="user_message",
        )
        item3 = MemoryItem.create(
            conversation_id="conv-2",
            content="Memory 3",
            memory_type=MemoryType.FACT,
            trust_classification=TrustClassification.UNTRUSTED_DATA,
            source="user",
            provenance="user_message",
        )
        
        MemoryProvider.store_memory(item1)
        MemoryProvider.store_memory(item2)
        MemoryProvider.store_memory(item3)
        
        # Get memory for conv-1
        memory = MemoryProvider.get_memory_by_conversation("conv-1")
        assert len(memory) == 2
        memory_ids = {m.memory_id for m in memory}
        assert item1.memory_id in memory_ids
        assert item2.memory_id in memory_ids
        assert item3.memory_id not in memory_ids
    
    def test_memory_provider_get_by_type(self):
        """Test MemoryProvider get memory by type."""
        from agent.memory import MemoryProvider, MemoryItem, MemoryType, TrustClassification
        
        fact1 = MemoryItem.create(
            conversation_id="conv-1",
            content="Fact 1",
            memory_type=MemoryType.FACT,
            trust_classification=TrustClassification.UNTRUSTED_DATA,
            source="user",
            provenance="user_message",
        )
        fact2 = MemoryItem.create(
            conversation_id="conv-1",
            content="Fact 2",
            memory_type=MemoryType.FACT,
            trust_classification=TrustClassification.UNTRUSTED_DATA,
            source="user",
            provenance="user_message",
        )
        decision = MemoryItem.create(
            conversation_id="conv-1",
            content="Decision 1",
            memory_type=MemoryType.DECISION,
            trust_classification=TrustClassification.UNTRUSTED_DATA,
            source="user",
            provenance="user_message",
        )
        
        MemoryProvider.store_memory(fact1)
        MemoryProvider.store_memory(fact2)
        MemoryProvider.store_memory(decision)
        
        # Get facts only
        facts = MemoryProvider.get_memory_by_type("conv-1", MemoryType.FACT)
        assert len(facts) == 2
        fact_ids = {f.memory_id for f in facts}
        assert fact1.memory_id in fact_ids
        assert fact2.memory_id in fact_ids
        assert decision.memory_id not in fact_ids
    
    def test_memory_provider_delete(self):
        """Test MemoryProvider delete memory."""
        from agent.memory import MemoryProvider, MemoryItem, MemoryType, TrustClassification
        
        item = MemoryItem.create(
            conversation_id="conv-1",
            content="Test",
            memory_type=MemoryType.FACT,
            trust_classification=TrustClassification.UNTRUSTED_DATA,
            source="user",
            provenance="user_message",
        )
        
        MemoryProvider.store_memory(item)
        
        # Verify exists
        assert MemoryProvider.get_memory_item(item.memory_id) is not None
        
        # Delete
        result = MemoryProvider.delete_memory(item.memory_id)
        assert result is True
        
        # Verify deleted
        assert MemoryProvider.get_memory_item(item.memory_id) is None
    
    def test_memory_provider_get_relevant(self):
        """Test MemoryProvider get relevant memory with priority ordering."""
        from agent.memory import MemoryProvider, MemoryItem, MemoryType, TrustClassification
        
        # Create memory items with different priorities
        objective = MemoryItem.create(
            conversation_id="conv-1",
            content="Active objective",
            memory_type=MemoryType.ACTIVE_OBJECTIVE,
            trust_classification=TrustClassification.UNTRUSTED_DATA,
            source="user",
            provenance="user_message",
        )
        question = MemoryItem.create(
            conversation_id="conv-1",
            content="Unresolved question",
            memory_type=MemoryType.UNRESOLVED_QUESTION,
            trust_classification=TrustClassification.UNTRUSTED_DATA,
            source="user",
            provenance="user_message",
        )
        fact = MemoryItem.create(
            conversation_id="conv-1",
            content="Important fact",
            memory_type=MemoryType.FACT,
            trust_classification=TrustClassification.UNTRUSTED_DATA,
            source="user",
            provenance="user_message",
        )
        
        MemoryProvider.store_memory(objective)
        MemoryProvider.store_memory(question)
        MemoryProvider.store_memory(fact)
        
        # Get relevant memory
        relevant = MemoryProvider.get_relevant_memory("conv-1", limit=10)
        
        # Should be ordered by priority
        assert len(relevant) == 3
        # Active objective should be first
        assert relevant[0].memory_type == MemoryType.ACTIVE_OBJECTIVE
        # Unresolved question should be second
        assert relevant[1].memory_type == MemoryType.UNRESOLVED_QUESTION
        # Fact should be third
        assert relevant[2].memory_type == MemoryType.FACT
    
    def test_memory_stats(self):
        """Test MemoryProvider statistics."""
        from agent.memory import MemoryProvider, MemoryItem, MemoryType, TrustClassification
        
        # Create memory items
        for i in range(5):
            item = MemoryItem.create(
                conversation_id="conv-1",
                content=f"Fact {i}",
                memory_type=MemoryType.FACT,
                trust_classification=TrustClassification.UNTRUSTED_DATA,
                source="user",
                provenance="user_message",
            )
            MemoryProvider.store_memory(item)
        
        for i in range(3):
            item = MemoryItem.create(
                conversation_id="conv-1",
                content=f"Decision {i}",
                memory_type=MemoryType.DECISION,
                trust_classification=TrustClassification.UNTRUSTED_DATA,
                source="user",
                provenance="user_message",
            )
            MemoryProvider.store_memory(item)
        
        stats = MemoryProvider.get_memory_stats()
        assert stats["total"] == 8
        assert stats["by_type"]["fact"] == 5
        assert stats["by_type"]["decision"] == 3


# =============================================================================
# Phase 5D: Memory Consolidation Tests
# =============================================================================

class TestPhase5D_MemoryConsolidation:
    """Test automatic memory consolidation."""
    
    def setup_method(self):
        """Set up test database."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.sqlite3', delete=False)
        self.temp_db.close()
        
        self.db_patch = patch('agent.memory.MEMORY_DB_PATH', Path(self.temp_db.name))
        self.db_patch.start()
        
        from agent.memory import _init_memory_db
        _init_memory_db()
    
    def teardown_method(self):
        """Clean up test database."""
        self.db_patch.stop()
        try:
            os.unlink(self.temp_db.name)
        except FileNotFoundError:
            pass
    
    def test_consolidation_not_needed(self):
        """Test consolidation when not needed."""
        from agent.memory import ConversationMemory, MemoryItem, MemoryType, TrustClassification
        
        # Create a few memory items (under limit)
        for i in range(10):
            item = MemoryItem.create(
                conversation_id="conv-1",
                content=f"Memory {i}",
                memory_type=MemoryType.RECENT,
                trust_classification=TrustClassification.UNTRUSTED_DATA,
                source="conversation",
                provenance="user_message",
            )
            ConversationMemory.store_conversation_memory(
                conversation_id="conv-1",
                content=f"Memory {i}",
                memory_type=MemoryType.RECENT,
                source="conversation",
                provenance="user_message",
                trust_classification=TrustClassification.UNTRUSTED_DATA,
            )
        
        result = ConversationMemory.consolidate_memory("conv-1", max_items=100)
        assert result["consolidated"] is False
        assert result["actions_taken"] == []
    
    def test_consolidation_creates_summary(self):
        """Test consolidation creates summary from excess messages."""
        from agent.memory import ConversationMemory, MemoryProvider, MemoryItem, MemoryType, TrustClassification
        
        # Create many recent messages (over limit)
        for i in range(60):
            item = MemoryItem.create(
                conversation_id="conv-1",
                content=f"Message {i}",
                memory_type=MemoryType.RECENT,
                trust_classification=TrustClassification.UNTRUSTED_DATA,
                source="conversation",
                provenance="user_message",
            )
            MemoryProvider.store_memory(item)
        
        result = ConversationMemory.consolidate_memory("conv-1", max_items=50)
        
        assert result["consolidated"] is True
        assert len(result["actions_taken"]) > 0
        
        # Check that summary was created
        memory = MemoryProvider.get_memory_by_conversation("conv-1")
        summary_items = [m for m in memory if m.memory_type == MemoryType.SUMMARY]
        assert len(summary_items) > 0
        
        # Check that some messages were deleted
        recent_items = [m for m in memory if m.memory_type == MemoryType.RECENT]
        assert len(recent_items) <= 50


# =============================================================================
# Integration Tests
# =============================================================================

class TestPhase5_Integration:
    """Integration tests for Phase 5 components."""
    
    def test_runtime_limits_integration(self):
        """Test RuntimeLimits integration with Owner Policy."""
        from agent.context import RuntimeLimits
        from security.owner_policy import load_policy, get_runtime_limits
        
        # Load policy
        policy = load_policy()
        assert hasattr(policy, 'runtime_limits')
        
        # Get limits
        limits = get_runtime_limits()
        
        # Create RuntimeLimits from policy
        runtime_limits = RuntimeLimits.from_owner_policy()
        
        # Verify all values match
        assert runtime_limits.max_context_messages == limits.max_context_messages
        assert runtime_limits.max_context_chars == limits.max_context_chars
        assert runtime_limits.max_execution_steps == limits.max_execution_steps
    
    def test_agent_loop_runtime_limits_integration(self):
        """Test AgentLoop integration with RuntimeLimits."""
        from agent.loop import AgentLoop
        from agent.context import RuntimeLimits
        
        # Test default construction
        loop1 = AgentLoop(MagicMock(), lambda *args, **kwargs: {})
        assert loop1.max_steps == 20
        assert loop1.runtime_limits.max_execution_steps == 20
        
        # Test custom limits
        custom = RuntimeLimits(
            max_context_messages=100,
            max_context_chars=64000,
            max_result_chars=8000,
            max_tool_calls=20,
            max_execution_steps=50,
            max_same_tool_calls=10,
            max_execution_time_seconds=600,
            max_pending_tasks=20,
            max_retries=5,
            max_total_output_chars=16000,
        )
        loop2 = AgentLoop(MagicMock(), lambda *args, **kwargs: {}, runtime_limits=custom)
        assert loop2.max_steps == 50
        assert loop2.runtime_limits.max_execution_steps == 50


# =============================================================================
# Security Tests
# =============================================================================

class TestPhase5_Security:
    """Security tests for Phase 5."""
    
    def test_runtime_limits_immutable(self):
        """Test that RuntimeLimits is immutable."""
        from agent.context import RuntimeLimits
        
        limits = RuntimeLimits()
        
        # Should not be able to modify
        with pytest.raises(AttributeError):
            limits.max_execution_steps = 100
    
    def test_task_immutable_state(self):
        """Test that TaskState is immutable."""
        from agent.state import TaskState
        
        state = TaskState(
            task_id="task-1",
            conversation_id="conv-1",
            request_id="req-1",
            owner_session_id="session-1",
            status="queued",
            current_step=0,
            tool_calls_count=0,
            retry_count=0,
            provider="provider-1",
            model="model-1",
            objective="Test",
            created_at="2024-01-01T00:00:00",
            updated_at="2024-01-01T00:00:00",
            started_at=None,
            finished_at=None,
        )
        
        # Should not be able to modify
        with pytest.raises(AttributeError):
            state.status = "completed"
    
    def test_memory_item_immutable(self):
        """Test that MemoryItem is immutable."""
        from agent.memory import MemoryItem, MemoryType, TrustClassification
        
        item = MemoryItem.create(
            conversation_id="conv-1",
            content="Test",
            memory_type=MemoryType.FACT,
            trust_classification=TrustClassification.UNTRUSTED_DATA,
            source="user",
            provenance="user_message",
        )
        
        # Should not be able to modify
        with pytest.raises(AttributeError):
            item.content = "Modified"


# =============================================================================
# Regression Tests
# =============================================================================

class TestPhase5_Regression:
    """Regression tests to ensure Phase 5 doesn't break existing functionality."""
    
    def test_agent_loop_still_works(self, monkeypatch, tmp_path):
        """Test that AgentLoop still works with new RuntimeLimits."""
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))
        
        from core import db
        monkeypatch.setattr(db, "DB_PATH", tmp_path / "conversation.sqlite3")
        
        from agent.loop import AgentLoop
        
        class FakeRouter:
            def chat(self, messages):
                return {"content": '{"type": "final", "content": "test answer"}'}
        
        loop = AgentLoop(FakeRouter(), lambda *args, **kwargs: {"ok": True})
        result = loop.run("conv-1", "test query", owner_token="test-token")
        
        assert "conversation_id" in result
        assert "answer" in result
        assert result["answer"] == "test answer"
    
    def test_context_engine_still_works(self):
        """Test that ContextEngine still works."""
        from agent.context import ContextEngine, ExecutionState, RuntimeLimits
        
        context = ContextEngine.build(
            user_text="test query",
            conversation_id="conv-1",
            owner_policy_context="test policy",
            conversation_messages=[],
            tool_results=None,
            execution_state=ExecutionState.initial("req-1", "conv-1"),
            runtime_limits=RuntimeLimits(),
            provider="test",
            model="test",
        )
        
        assert context is not None
        assert hasattr(context, "messages")
        assert hasattr(context, "tools")
        assert hasattr(context, "context_hash")
