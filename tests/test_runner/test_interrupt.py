"""Runner interrupt routing at the HTTP and NDJSON boundaries."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi import FastAPI

from conductor.aca_runner import server
from conductor.config.schema import ProviderSettings
from conductor.providers.aca import AcaRuntimeProvider
from conductor.providers.base import AgentOutput
from conductor.runner.protocol import RunnerHealthResponse


class _InterruptibleProvider:
    started: dict[str, asyncio.Event] = {}
    finish: dict[str, asyncio.Event] = {}

    def __init__(self, **kwargs: Any) -> None:
        pass

    async def execute(
        self, agent: Any, context: dict[str, Any], prompt: str, **kwargs: Any
    ) -> AgentOutput:
        execution_id = context["execution_id"]
        self.started[execution_id].set()
        interrupt = kwargs["interrupt_signal"]
        if interrupt is None:
            await self.finish[execution_id].wait()
            partial = False
        else:
            completed, pending = await asyncio.wait(
                [
                    asyncio.create_task(interrupt.wait()),
                    asyncio.create_task(self.finish[execution_id].wait()),
                ],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            partial = interrupt.is_set()
        return AgentOutput(
            content={"execution_id": execution_id}, raw_response=None, partial=partial
        )

    async def close(self) -> None:
        pass


@pytest.fixture(autouse=True)
def _fake_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    _InterruptibleProvider.started = {}
    _InterruptibleProvider.finish = {}
    monkeypatch.setattr(server, "CopilotProvider", _InterruptibleProvider)
    monkeypatch.delenv("ACA_RUNNER_AUTH_TOKEN", raising=False)


@asynccontextmanager
async def _client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://runner"
        ) as client,
    ):
        yield client


def _body(execution_id: str, *, legacy: bool = False) -> dict[str, Any]:
    body: dict[str, Any] = {
        "agent": {"name": "agent"},
        "rendered_prompt": "task",
        "context": {"execution_id": execution_id},
    }
    if not legacy:
        body["execution_id"] = execution_id
    _InterruptibleProvider.started[execution_id] = asyncio.Event()
    _InterruptibleProvider.finish[execution_id] = asyncio.Event()
    return body


def _terminal(response: httpx.Response) -> dict[str, Any]:
    return json.loads(response.text.splitlines()[-1])


async def test_interrupt_targets_only_one_concurrent_agent() -> None:
    # Requirement: main-loop agent calls are interruptible without pausing a sibling;
    # parallel/for-each interrupt propagation is not promised by the engine today (N5).
    app = server.create_app()
    async with _client(app) as client:
        first = asyncio.create_task(client.post("/execute", json=_body("first")))
        second = asyncio.create_task(client.post("/execute", json=_body("second")))
        await asyncio.wait_for(
            asyncio.gather(*(event.wait() for event in _InterruptibleProvider.started.values())),
            timeout=5,
        )
        response = await client.post("/interrupt", json={"execution_id": "first"})
        assert response.status_code == 200
        assert not _InterruptibleProvider.finish["second"].is_set()
        _InterruptibleProvider.finish["second"].set()
        first_response, second_response = await asyncio.wait_for(
            asyncio.gather(first, second), timeout=5
        )
        assert _terminal(first_response)["data"]["partial"] is True
        assert _terminal(first_response)["data"]["content"]["execution_id"] == "first"
        assert _terminal(second_response)["data"]["partial"] is False


async def test_interrupt_unknown_returns_404() -> None:
    # Requirement: an unknown execution cannot interrupt another running call.
    async with _client(server.create_app()) as client:
        response = await client.post("/interrupt", json={"execution_id": "missing"})
    assert response.status_code == 404


async def test_interrupt_duplicate_active_identity_returns_409() -> None:
    # Requirement: two calls cannot claim the same interrupt target.
    async with _client(server.create_app()) as client:
        first = asyncio.create_task(client.post("/execute", json=_body("shared")))
        await asyncio.wait_for(_InterruptibleProvider.started["shared"].wait(), timeout=5)
        duplicate = await client.post(
            "/execute",
            json={"agent": {"name": "agent"}, "rendered_prompt": "task", "execution_id": "shared"},
        )
        _InterruptibleProvider.finish["shared"].set()
        completed = await asyncio.wait_for(first, timeout=5)
    assert duplicate.status_code == 409
    assert _terminal(completed)["data"]["partial"] is False


async def test_interrupt_late_and_repeated_return_409() -> None:
    # Requirement: already signaled and terminal identities cannot be signaled again.
    app = server.create_app()
    async with _client(app) as client:
        request = asyncio.create_task(client.post("/execute", json=_body("done")))
        await asyncio.wait_for(_InterruptibleProvider.started["done"].wait(), timeout=5)
        first = await client.post("/interrupt", json={"execution_id": "done"})
        repeated = await client.post("/interrupt", json={"execution_id": "done"})
        result = await asyncio.wait_for(request, timeout=5)
        late = await client.post("/interrupt", json={"execution_id": "done"})
    assert first.status_code == 200
    assert repeated.status_code == 409
    assert _terminal(result)["data"]["partial"] is True
    assert late.status_code == 409


async def test_interrupt_degraded_handshake(caplog: pytest.LogCaptureFixture) -> None:
    # Requirement: only v2 images advertising interrupt can enable realm interrupt;
    # v1 and missing-feature images keep interrupt=False and use legacy abort-read.
    async with _client(server.create_app()) as client:
        response = await client.get("/health")
    advertised = RunnerHealthResponse.model_validate(response.json())
    assert advertised.protocol_version == 2
    assert "interrupt" in (advertised.features or [])
    for old in ({"ready": True, "protocol_version": 1}, {"ready": True, "protocol_version": 2}):
        health = RunnerHealthResponse.model_validate(old)
        assert not (health.protocol_version == 2 and "interrupt" in (health.features or []))
        if health.protocol_version == 1:
            AcaRuntimeProvider._warn_on_version_skew(object.__new__(AcaRuntimeProvider), health)
    assert any(record.name == "conductor.providers.aca" for record in caplog.records)


async def test_interrupt_auth_and_bad_input(monkeypatch: pytest.MonkeyPatch) -> None:
    # Requirement: interruption uses the execute token gate and rejects malformed IDs.
    monkeypatch.setenv("ACA_RUNNER_AUTH_TOKEN", "runner-token")
    async with _client(server.create_app()) as client:
        unauthorized = await client.post("/interrupt", json={"execution_id": "one"})
        malformed = await client.post(
            "/interrupt", content=b"{broken", headers={"X-Conductor-Runner-Token": "runner-token"}
        )
        missing = await client.post(
            "/interrupt", json={}, headers={"X-Conductor-Runner-Token": "runner-token"}
        )
    assert unauthorized.status_code == 401
    assert malformed.status_code == 422
    assert missing.status_code == 422


async def test_legacy_aca_interrupt_reaches_runner_with_identifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Requirement: the existing legacy ACA POST, which has no JSON body, works
    # against a new runner through the gateway's identifier routing.
    monkeypatch.setenv("COPILOT_GITHUB_TOKEN", "host-token")
    with patch("conductor.providers.aca.AZURE_IDENTITY_AVAILABLE", True):
        legacy = AcaRuntimeProvider(
            provider_settings=ProviderSettings(name="aca", pool_endpoint="https://pool.example.com")
        )
    app = server.create_app()
    async with _client(app) as client:
        legacy._get_access_token = AsyncMock(return_value="transport-token")
        legacy._http_client = client
        request = asyncio.create_task(
            client.post(
                "/execute", params={"identifier": "legacy"}, json=_body("legacy", legacy=True)
            )
        )
        await asyncio.wait_for(_InterruptibleProvider.started["legacy"].wait(), timeout=5)
        await legacy._send_interrupt("legacy")
        result = await asyncio.wait_for(request, timeout=5)
    assert _terminal(result)["data"]["partial"] is True


async def test_legacy_aca_identifier_can_be_reused_after_completion() -> None:
    # Requirement: the legacy gateway's sequential session reuse remains valid.
    async with _client(server.create_app()) as client:
        first_body = _body("legacy-one", legacy=True)
        first = asyncio.create_task(
            client.post("/execute", params={"identifier": "session"}, json=first_body)
        )
        await asyncio.wait_for(_InterruptibleProvider.started["legacy-one"].wait(), timeout=5)
        _InterruptibleProvider.finish["legacy-one"].set()
        assert (await asyncio.wait_for(first, timeout=5)).status_code == 200
        second_body = _body("legacy-two", legacy=True)
        second = asyncio.create_task(
            client.post("/execute", params={"identifier": "session"}, json=second_body)
        )
        await asyncio.wait_for(_InterruptibleProvider.started["legacy-two"].wait(), timeout=5)
        _InterruptibleProvider.finish["legacy-two"].set()
        assert (await asyncio.wait_for(second, timeout=5)).status_code == 200
