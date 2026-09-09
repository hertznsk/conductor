"""Unit tests for the ProviderRegistry."""

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from conductor.config.schema import (
    AgentDef,
    RuntimeConfig,
    WorkflowConfig,
    WorkflowDef,
)
from conductor.exceptions import ProviderError
from conductor.providers.base import AgentOutput, AgentProvider
from conductor.providers.registry import ProviderRegistry


class MockProvider(AgentProvider, abstract=True):
    """Mock provider for testing."""

    def __init__(self, provider_type: str = "test") -> None:
        self.provider_type = provider_type
        self.closed = False

    async def execute(
        self,
        agent: AgentDef,
        context: dict[str, Any],
        rendered_prompt: str,
        tools: list[str] | None = None,
        interrupt_signal: asyncio.Event | None = None,
        event_callback=None,
        skill_directories: list[str] | None = None,
        custom_agents: list[dict[str, Any]] | None = None,
        extra_mcp_servers: dict[str, Any] | None = None,
    ) -> AgentOutput:
        return AgentOutput(content={"result": "mock"}, raw_response="mock")

    async def validate_connection(self) -> bool:
        return True

    async def close(self) -> None:
        self.closed = True


def create_test_config(
    default_provider: str = "copilot",
    agents: list[AgentDef] | None = None,
) -> WorkflowConfig:
    """Create a minimal test config."""
    if agents is None:
        agents = [
            AgentDef(
                name="agent1",
                prompt="test prompt",
            )
        ]

    return WorkflowConfig(
        workflow=WorkflowDef(
            name="test-workflow",
            entry_point="agent1",
            runtime=RuntimeConfig(provider=default_provider),
        ),
        agents=agents,
        output={"result": "{{ agent1.output.result }}"},
    )


class TestProviderRegistryBasics:
    """Basic functionality tests for ProviderRegistry."""

    def test_initialization(self) -> None:
        """Test registry initializes correctly."""
        config = create_test_config(default_provider="copilot")
        registry = ProviderRegistry(config)

        assert registry.default_provider_type == "copilot"
        assert len(registry.get_active_providers()) == 0

    def test_default_provider_type(self) -> None:
        """Test default provider type is read from config."""
        config = create_test_config(default_provider="claude")
        registry = ProviderRegistry(config)

        assert registry.default_provider_type == "claude"

    def test_is_provider_active_when_empty(self) -> None:
        """Test is_provider_active returns False for inactive providers."""
        config = create_test_config()
        registry = ProviderRegistry(config)

        assert not registry.is_provider_active("copilot")
        assert not registry.is_provider_active("claude")


class TestProviderResolution:
    """Tests for provider type resolution logic."""

    def test_get_provider_type_uses_workflow_default(self) -> None:
        """Test agent without provider uses workflow default."""
        config = create_test_config(default_provider="copilot")
        registry = ProviderRegistry(config)

        agent = AgentDef(name="test", prompt="test", provider=None)
        provider_type = registry._get_provider_type_for_agent(agent)

        assert provider_type == "copilot"

    def test_get_provider_type_uses_agent_override(self) -> None:
        """Test agent with provider override uses that provider."""
        config = create_test_config(default_provider="copilot")
        registry = ProviderRegistry(config)

        agent = AgentDef(name="test", prompt="test", provider="claude")
        provider_type = registry._get_provider_type_for_agent(agent)

        assert provider_type == "claude"


class TestProviderCaching:
    """Tests for provider caching behavior."""

    @patch("conductor.providers.registry.create_provider")
    @pytest.mark.asyncio
    async def test_providers_are_cached(self, mock_create: MagicMock) -> None:
        """Test that providers are cached and reused."""
        mock_provider = MockProvider()
        mock_create.return_value = mock_provider

        config = create_test_config(default_provider="copilot")
        registry = ProviderRegistry(config)

        agent1 = AgentDef(name="agent1", prompt="test")
        agent2 = AgentDef(name="agent2", prompt="test")

        # Get provider for two agents with same provider type
        provider1 = await registry.get_provider(agent1)
        provider2 = await registry.get_provider(agent2)

        # Should be the same instance
        assert provider1 is provider2

        # create_provider should only be called once
        assert mock_create.call_count == 1

    @patch("conductor.providers.registry.create_provider")
    @pytest.mark.asyncio
    async def test_different_providers_created_separately(self, mock_create: MagicMock) -> None:
        """Test that different provider types create different instances."""
        copilot_provider = MockProvider("copilot")
        claude_provider = MockProvider("claude")

        async def create_side_effect(**kwargs: Any) -> MockProvider:
            if kwargs.get("provider_type") == "copilot":
                return copilot_provider
            return claude_provider

        mock_create.side_effect = create_side_effect

        config = create_test_config(default_provider="copilot")
        registry = ProviderRegistry(config)

        agent_copilot = AgentDef(name="agent1", prompt="test", provider=None)
        agent_claude = AgentDef(name="agent2", prompt="test", provider="claude")

        provider1 = await registry.get_provider(agent_copilot)
        provider2 = await registry.get_provider(agent_claude)

        # Should be different instances
        assert provider1 is not provider2
        assert provider1.provider_type == "copilot"
        assert provider2.provider_type == "claude"

        # create_provider should be called twice
        assert mock_create.call_count == 2


class TestProviderLifecycle:
    """Tests for provider lifecycle management."""

    @patch("conductor.providers.registry.create_provider")
    @pytest.mark.asyncio
    async def test_close_closes_all_providers(self, mock_create: MagicMock) -> None:
        """Test that close() closes all active providers."""
        copilot_provider = MockProvider("copilot")
        claude_provider = MockProvider("claude")

        async def create_side_effect(**kwargs: Any) -> MockProvider:
            if kwargs.get("provider_type") == "copilot":
                return copilot_provider
            return claude_provider

        mock_create.side_effect = create_side_effect

        config = create_test_config(default_provider="copilot")
        registry = ProviderRegistry(config)

        # Create both providers
        agent_copilot = AgentDef(name="agent1", prompt="test", provider=None)
        agent_claude = AgentDef(name="agent2", prompt="test", provider="claude")
        await registry.get_provider(agent_copilot)
        await registry.get_provider(agent_claude)

        # Verify providers are active
        assert registry.is_provider_active("copilot")
        assert registry.is_provider_active("claude")

        # Close registry
        await registry.close()

        # Verify both providers were closed
        assert copilot_provider.closed
        assert claude_provider.closed

        # Verify registry is empty
        assert len(registry.get_active_providers()) == 0

    @patch("conductor.providers.registry.create_provider")
    @pytest.mark.asyncio
    async def test_context_manager_closes_providers(self, mock_create: MagicMock) -> None:
        """Test that async context manager closes providers on exit."""
        mock_provider = MockProvider()
        mock_create.return_value = mock_provider

        config = create_test_config()

        async with ProviderRegistry(config) as registry:
            agent = AgentDef(name="agent1", prompt="test")
            await registry.get_provider(agent)
            assert not mock_provider.closed

        # After context exit, provider should be closed
        assert mock_provider.closed

    @patch("conductor.providers.registry.create_provider")
    @pytest.mark.asyncio
    async def test_context_manager_closes_on_exception(self, mock_create: MagicMock) -> None:
        """Test that async context manager closes providers even on exception."""
        mock_provider = MockProvider()
        mock_create.return_value = mock_provider

        config = create_test_config()

        with pytest.raises(ValueError, match="test error"):
            async with ProviderRegistry(config) as registry:
                agent = AgentDef(name="agent1", prompt="test")
                await registry.get_provider(agent)
                raise ValueError("test error")

        # Provider should still be closed
        assert mock_provider.closed


class TestLazyInstantiation:
    """Tests for lazy provider instantiation."""

    @patch("conductor.providers.registry.create_provider")
    @pytest.mark.asyncio
    async def test_providers_created_lazily(self, mock_create: MagicMock) -> None:
        """Test that providers are not created until first use."""
        mock_provider = MockProvider()
        mock_create.return_value = mock_provider

        config = create_test_config()
        registry = ProviderRegistry(config)

        # No providers should be created yet
        assert mock_create.call_count == 0
        assert len(registry.get_active_providers()) == 0

        # Get provider for an agent
        agent = AgentDef(name="agent1", prompt="test")
        await registry.get_provider(agent)

        # Now provider should be created
        assert mock_create.call_count == 1
        assert len(registry.get_active_providers()) == 1

    @patch("conductor.providers.registry.create_provider")
    @pytest.mark.asyncio
    async def test_only_needed_providers_created(self, mock_create: MagicMock) -> None:
        """Test that only providers actually needed are created."""
        mock_provider = MockProvider()
        mock_create.return_value = mock_provider

        config = create_test_config(default_provider="copilot")
        registry = ProviderRegistry(config)

        # Only use copilot provider (no claude agents)
        agent = AgentDef(name="agent1", prompt="test", provider=None)
        await registry.get_provider(agent)

        # Only copilot should be created
        assert registry.is_provider_active("copilot")
        assert not registry.is_provider_active("claude")


class TestConfigPassing:
    """Tests for config passing to providers."""

    @patch("conductor.providers.registry.create_provider")
    @pytest.mark.asyncio
    async def test_runtime_config_passed_to_provider(self, mock_create: MagicMock) -> None:
        """Test that runtime config is passed when creating providers."""
        mock_provider = MockProvider()
        mock_create.return_value = mock_provider

        # Create config with runtime settings
        config = WorkflowConfig(
            workflow=WorkflowDef(
                name="test-workflow",
                entry_point="agent1",
                runtime=RuntimeConfig(
                    provider="copilot",
                    default_model="gpt-4",
                    temperature=0.7,
                    max_tokens=4096,
                    timeout=60.0,
                    default_reasoning_effort="high",
                ),
            ),
            agents=[AgentDef(name="agent1", prompt="test")],
            output={"result": "test"},
        )

        registry = ProviderRegistry(config)
        agent = AgentDef(name="agent1", prompt="test")
        await registry.get_provider(agent)

        # Verify create_provider was called with config values
        mock_create.assert_called_once_with(
            provider_type="copilot",
            validate=True,
            mcp_servers=None,
            default_model="gpt-4",
            temperature=0.7,
            max_tokens=4096,
            timeout=60.0,
            max_session_seconds=None,
            max_agent_iterations=None,
            idle_timeout_seconds=None,
            max_idle_recovery_attempts=None,
            default_reasoning_effort="high",
            provider_settings=config.workflow.runtime.provider,
            tool_output=config.workflow.runtime.tool_output,
        )

    @patch("conductor.providers.registry.create_provider")
    @pytest.mark.asyncio
    async def test_mcp_servers_passed_to_provider(self, mock_create: MagicMock) -> None:
        """Test that MCP servers are passed when creating providers."""
        mock_provider = MockProvider()
        mock_create.return_value = mock_provider

        config = create_test_config()
        mcp_servers = {"test-server": {"type": "stdio", "command": "test"}}

        registry = ProviderRegistry(config, mcp_servers=mcp_servers)
        agent = AgentDef(name="agent1", prompt="test")
        await registry.get_provider(agent)

        # Verify MCP servers were passed
        call_kwargs = mock_create.call_args[1]
        assert call_kwargs["mcp_servers"] == mcp_servers


# A hang guard, not a timing assertion. No assertion below depends on its
# value: it exists only so a broken implementation fails the test instead of
# stranding a task and blocking the suite.
_HANG_GUARD_SECONDS = 5.0


async def _finish(*tasks: "asyncio.Task[Any]") -> list[Any]:
    """Await tasks under the hang guard, cancelling any survivor."""
    gathered = asyncio.gather(*tasks)
    try:
        return await asyncio.wait_for(gathered, _HANG_GUARD_SECONDS)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class _ObservableLock:
    """Delegates to a real ``asyncio.Lock`` and reports contention.

    Serialization semantics are the real lock's — this wrapper only observes.
    ``contenders`` counts callers that found the lock already held, which is
    the signal the tests use to prove a second caller has genuinely reached
    the registry lock (rather than merely having had a task created for it).
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self.entries = 0
        self.contenders = 0
        self._target: int | None = None
        self._reached = asyncio.Event()

    async def __aenter__(self) -> None:
        self.entries += 1
        if self._lock.locked():
            self.contenders += 1
            if self._target is not None and self.contenders >= self._target:
                self._reached.set()
        # The caller parks here while the lock is held. The waiter below can
        # only be scheduled once that has happened, so observing ``_reached``
        # proves the contender is inside ``acquire()``.
        await self._lock.acquire()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._lock.release()

    def locked(self) -> bool:
        return self._lock.locked()

    async def wait_until_contended(self, count: int = 1) -> None:
        """Block until ``count`` callers have queued behind the held lock."""
        self._target = count
        if self.contenders >= count:
            self._reached.set()
        await asyncio.wait_for(self._reached.wait(), _HANG_GUARD_SECONDS)


class _NullLock:
    """Test-only neutralisation of the registry lock.

    ``__aenter__`` awaits nothing, so it introduces no suspension point and
    cannot serialize anything — reproducing the pre-fix unlocked behaviour
    without editing production code.
    """

    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        return False

    def locked(self) -> bool:
        return False


class _ConstructionSeam:
    """A controlled ``create_provider`` stand-in.

    Every call registers its arrival and then blocks until the test releases
    it, so the test decides the interleaving instead of the scheduler.
    ``all_arrived`` fires once ``expected`` callers are inside the factory —
    which under correct serialization must never happen for more than one.
    """

    def __init__(self, expected: int = 2) -> None:
        self.calls = 0
        self.built: list[MockProvider] = []
        self.first_arrived = asyncio.Event()
        self.all_arrived = asyncio.Event()
        self.release = asyncio.Event()
        self._expected = expected

    async def __call__(self, **_kwargs: Any) -> MockProvider:
        self.calls += 1
        self.first_arrived.set()
        if self.calls >= self._expected:
            self.all_arrived.set()
        await self.release.wait()
        provider = MockProvider()
        self.built.append(provider)
        return provider


class TestConcurrentProviderCreation:
    """Provider identity per type must be stable under concurrency.

    ``_get_or_create_provider`` is a check-then-act: it tests the cache, then
    ``await``s ``create_provider(...)``, then publishes. Two agents resolving
    the same provider type concurrently could each miss the cache, each
    construct an instance, and the second publication replace the first — so
    the two agents hold different objects for one provider type. That is
    invisible for a stateless provider and load-bearing for one that keeps
    per-instance state.

    The interleaving is driven entirely by explicit events: a construction
    seam the test releases, and lock-contention observation that proves the
    second caller has *reached the lock* before the first is released.
    Creating a task is not evidence that it ran, so no test here relies on
    task-creation order, sleeps, or timing thresholds.
    """

    @pytest.mark.asyncio
    async def test_second_caller_blocks_on_the_lock_and_both_share_one_instance(
        self,
    ) -> None:
        """The decisive case: contention is observed before release."""
        config = create_test_config(default_provider="copilot")
        registry = ProviderRegistry(config)
        lock = _ObservableLock()
        registry._provider_lock = lock  # type: ignore[assignment]
        seam = _ConstructionSeam(expected=2)

        agent_a = AgentDef(name="agent_a", prompt="test")
        agent_b = AgentDef(name="agent_b", prompt="test")

        with patch("conductor.providers.registry.create_provider", seam):
            first = asyncio.create_task(registry.get_provider(agent_a))
            # 1. First construction is paused inside the seam, holding the lock.
            await asyncio.wait_for(seam.first_arrived.wait(), _HANG_GUARD_SECONDS)
            assert lock.locked()

            second = asyncio.create_task(registry.get_provider(agent_b))
            # 2. Second caller has reached the lock and is queued behind it.
            await lock.wait_until_contended(1)

            # Serialization means it cannot have reached construction at all.
            assert not seam.all_arrived.is_set()
            assert seam.calls == 1

            # 3. Release the first construction.
            seam.release.set()
            provider_a, provider_b = await _finish(first, second)

        # 4. One construction; both callers hold the same object.
        assert seam.calls == 1
        assert len(seam.built) == 1
        assert provider_a is provider_b
        assert provider_a is seam.built[0]
        assert len(registry.get_active_providers()) == 1

    @pytest.mark.asyncio
    async def test_without_the_lock_the_same_harness_yields_two_constructions(
        self,
    ) -> None:
        """Control: proves this harness exposes the original unlocked race.

        Identical seam, lock neutralised in the test only. Both callers are
        held inside construction before either is released, so the pre-fix
        interleaving is forced rather than hoped for.
        """
        config = create_test_config(default_provider="copilot")
        registry = ProviderRegistry(config)
        registry._provider_lock = _NullLock()  # type: ignore[assignment]
        seam = _ConstructionSeam(expected=2)

        agent_a = AgentDef(name="agent_a", prompt="test")
        agent_b = AgentDef(name="agent_b", prompt="test")

        with patch("conductor.providers.registry.create_provider", seam):
            first = asyncio.create_task(registry.get_provider(agent_a))
            second = asyncio.create_task(registry.get_provider(agent_b))
            # Both callers are inside construction simultaneously — the state
            # the real lock makes unreachable.
            await asyncio.wait_for(seam.all_arrived.wait(), _HANG_GUARD_SECONDS)
            assert seam.calls == 2

            seam.release.set()
            provider_a, provider_b = await _finish(first, second)

        assert seam.calls == 2
        assert len(seam.built) == 2
        assert provider_a is not provider_b
        # The later publication won, so one caller holds an unpublished object.
        assert len(registry.get_active_providers()) == 1

    @pytest.mark.asyncio
    async def test_all_waiters_reuse_the_instance_the_winner_published(self) -> None:
        """Several queued callers re-check the cache instead of constructing."""
        config = create_test_config(default_provider="copilot")
        registry = ProviderRegistry(config)
        lock = _ObservableLock()
        registry._provider_lock = lock  # type: ignore[assignment]
        seam = _ConstructionSeam(expected=2)

        agents = [AgentDef(name=f"agent_{i}", prompt="test") for i in range(4)]

        with patch("conductor.providers.registry.create_provider", seam):
            winner = asyncio.create_task(registry.get_provider(agents[0]))
            await asyncio.wait_for(seam.first_arrived.wait(), _HANG_GUARD_SECONDS)

            waiters = [asyncio.create_task(registry.get_provider(a)) for a in agents[1:]]
            # All three waiters are queued behind the held lock.
            await lock.wait_until_contended(3)
            assert seam.calls == 1

            seam.release.set()
            results = await _finish(winner, *waiters)

        assert seam.calls == 1
        assert all(result is results[0] for result in results)
        assert len(registry.get_active_providers()) == 1

    @pytest.mark.asyncio
    async def test_creation_failure_reaches_every_waiter_and_caches_nothing(self) -> None:
        """A failure propagates unchanged, caches nothing, strands nobody."""
        config = create_test_config(default_provider="copilot")
        registry = ProviderRegistry(config)
        lock = _ObservableLock()
        registry._provider_lock = lock  # type: ignore[assignment]

        arrived = asyncio.Event()
        release = asyncio.Event()
        calls = 0

        async def failing_create(**_kwargs: Any) -> MockProvider:
            nonlocal calls
            calls += 1
            arrived.set()
            await release.wait()
            raise ProviderError("construction failed")

        agent_a = AgentDef(name="agent_a", prompt="test")
        agent_b = AgentDef(name="agent_b", prompt="test")

        with patch("conductor.providers.registry.create_provider", failing_create):
            first = asyncio.create_task(registry.get_provider(agent_a))
            await asyncio.wait_for(arrived.wait(), _HANG_GUARD_SECONDS)
            second = asyncio.create_task(registry.get_provider(agent_b))
            await lock.wait_until_contended(1)

            release.set()
            gathered = asyncio.gather(first, second, return_exceptions=True)
            outcomes = await asyncio.wait_for(gathered, _HANG_GUARD_SECONDS)

        # The waiter re-checked an empty cache and retried construction, so
        # both callers see a real ProviderError rather than one being stranded.
        assert len(outcomes) == 2
        for outcome in outcomes:
            assert isinstance(outcome, ProviderError)
        assert len(registry.get_active_providers()) == 0
        assert not lock.locked()

        # Nothing was poisoned and no lock was left held: a later attempt works.
        recovered = MockProvider()

        async def working_create(**_kwargs: Any) -> MockProvider:
            return recovered

        with patch("conductor.providers.registry.create_provider", working_create):
            assert await registry.get_provider(agent_a) is recovered

    @pytest.mark.asyncio
    async def test_cached_read_completes_while_the_real_lock_is_held(self) -> None:
        """The fast path must not touch the lock — proven against the real one.

        This is a fast-path property, not the race proof: the lock the
        registry built in ``__init__`` is held for the duration, so a cached
        read that acquired it could not return at all.
        """
        config = create_test_config(default_provider="copilot")
        registry = ProviderRegistry(config)
        agent = AgentDef(name="agent_a", prompt="test")
        provider = MockProvider()

        async def working_create(**_kwargs: Any) -> MockProvider:
            return provider

        with patch("conductor.providers.registry.create_provider", working_create):
            assert await registry.get_provider(agent) is provider

            production_lock = registry._provider_lock
            async with production_lock:
                assert production_lock.locked()
                cached = await asyncio.wait_for(registry.get_provider(agent), _HANG_GUARD_SECONDS)
                assert cached is provider

        assert not registry._provider_lock.locked()

    @pytest.mark.asyncio
    async def test_cached_read_does_not_enter_the_lock_context(self) -> None:
        """Corroborates the fast path by counting lock entries."""
        config = create_test_config(default_provider="copilot")
        registry = ProviderRegistry(config)
        lock = _ObservableLock()
        registry._provider_lock = lock  # type: ignore[assignment]

        agent = AgentDef(name="agent_a", prompt="test")
        provider = MockProvider()

        async def working_create(**_kwargs: Any) -> MockProvider:
            return provider

        with patch("conductor.providers.registry.create_provider", working_create):
            await registry.get_provider(agent)
            assert lock.entries == 1
            await registry.get_provider(agent)
            await registry.get_provider(agent)

        assert lock.entries == 1
        assert lock.contenders == 0
        assert not lock.locked()

    @pytest.mark.asyncio
    async def test_distinct_types_resolve_concurrently_to_distinct_instances(self) -> None:
        """Serializing creation must not collapse or deadlock distinct types."""
        built: dict[str, MockProvider] = {}

        async def per_type_create(**kwargs: Any) -> MockProvider:
            provider = MockProvider(provider_type=kwargs["provider_type"])
            built[kwargs["provider_type"]] = provider
            return provider

        config = create_test_config(default_provider="copilot")
        registry = ProviderRegistry(config)
        copilot_agent = AgentDef(name="a", prompt="test", provider="copilot")
        claude_agent = AgentDef(name="b", prompt="test", provider="claude")

        with patch("conductor.providers.registry.create_provider", per_type_create):
            gathered = asyncio.gather(
                registry.get_provider(copilot_agent),
                registry.get_provider(claude_agent),
            )
            copilot_provider, claude_provider = await asyncio.wait_for(
                gathered, _HANG_GUARD_SECONDS
            )

        assert copilot_provider is not claude_provider
        assert copilot_provider is built["copilot"]
        assert claude_provider is built["claude"]
        assert len(registry.get_active_providers()) == 2
