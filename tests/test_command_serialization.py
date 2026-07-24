"""Concurrency tests for UtecBleDevice.execute() command serialization."""

import asyncio

import pytest

from custom_components.ultraloq_ble.utecio.ble.device import (
    UtecBleDevice,
    UtecBleDeviceBusyError,
)
from custom_components.ultraloq_ble.utecio.ble.lock import UtecBleLock


def _device() -> UtecBleDevice:
    return UtecBleDevice(
        uid="123456",
        password="987654",
        mac_uuid="AA:BB:CC:DD:EE:FF",
        device_name="Fixture Lock",
        device_model="U-Bolt",
    )


def _install_recording_stub(device: UtecBleDevice, gate: asyncio.Event | None = None):
    """Replace send_requests with a stub that records and clears _requests.

    Mirrors the real drain-then-clear behavior. If `gate` is provided, the
    stub waits on it while still holding the caller's lock, so tests can force
    a controlled interleaving window.
    """

    sent: list[list] = []

    async def fake_send_requests() -> bool:
        if gate is not None:
            await gate.wait()
        else:
            await asyncio.sleep(0)
        sent.append(list(device._requests))
        device._requests.clear()
        return True

    device.send_requests = fake_send_requests
    return sent


@pytest.mark.asyncio
async def test_concurrent_execute_calls_do_not_cross_drain():
    """Two interleaved execute() calls each send only their own commands."""

    device = _device()
    gate_a = asyncio.Event()
    gate_b = asyncio.Event()
    sent_a: list[list] = []
    sent_b: list[list] = []

    async def fake_send_requests() -> bool:
        # Route the stub behavior based on which commands are present so
        # each caller waits on its own gate.
        if "cmd-a" in device._requests:
            await gate_a.wait()
            sent_a.append(list(device._requests))
        else:
            await gate_b.wait()
            sent_b.append(list(device._requests))
        device._requests.clear()
        return True

    device.send_requests = fake_send_requests

    def queue_a():
        device._requests.append("cmd-a")

    def queue_b():
        device._requests.append("cmd-b")

    task_a = asyncio.create_task(device.execute(queue_a))
    task_b = asyncio.create_task(device.execute(queue_b))

    # Give both tasks a chance to start; only one should actually be inside
    # send_requests at a time because of the command lock.
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    # Whichever caller acquired the lock first is now blocked on its gate.
    # Release both gates; since execute() serializes, the second caller
    # cannot have queued/sent until the first fully releases the lock.
    gate_a.set()
    gate_b.set()

    result_a, result_b = await asyncio.gather(task_a, task_b)

    assert result_a is True
    assert result_b is True
    assert sent_a == [["cmd-a"]]
    assert sent_b == [["cmd-b"]]


@pytest.mark.asyncio
async def test_poll_skips_when_busy():
    """skip_if_busy returns False without raising or invoking queue_commands."""

    device = _device()
    holder_gate = asyncio.Event()
    _install_recording_stub(device, gate=holder_gate)

    def queue_holder():
        device._requests.append("holder-cmd")

    holder_task = asyncio.create_task(device.execute(queue_holder))
    await asyncio.sleep(0)
    assert device.is_busy is True

    queue_calls = []

    def queue_poll():
        queue_calls.append(True)
        device._requests.append("poll-cmd")

    result = await device.execute(queue_poll, skip_if_busy=True)

    assert result is False
    assert queue_calls == []

    holder_gate.set()
    await holder_task


@pytest.mark.asyncio
async def test_command_waits_when_busy_and_sends_after_release():
    """A non-skip execute() blocks until the holder releases, then sends."""

    device = _device()
    holder_gate = asyncio.Event()
    order: list[str] = []
    sent: list[list] = []

    async def fake_send_requests() -> bool:
        if "holder-cmd" in device._requests:
            await holder_gate.wait()
            order.append("holder-sent")
        else:
            order.append("waiter-sent")
        sent.append(list(device._requests))
        device._requests.clear()
        return True

    device.send_requests = fake_send_requests

    def queue_holder():
        device._requests.append("holder-cmd")

    def queue_waiter():
        device._requests.append("waiter-cmd")

    holder_task = asyncio.create_task(device.execute(queue_holder))
    await asyncio.sleep(0)
    assert device.is_busy is True

    waiter_task = asyncio.create_task(device.execute(queue_waiter))
    await asyncio.sleep(0)

    # The waiter must not have run yet; it is blocked acquiring the lock.
    assert order == []

    holder_gate.set()
    result_holder, result_waiter = await asyncio.gather(holder_task, waiter_task)

    assert result_holder is True
    assert result_waiter is True
    assert order == ["holder-sent", "waiter-sent"]
    assert sent == [["holder-cmd"], ["waiter-cmd"]]


@pytest.mark.asyncio
async def test_acquire_timeout_raises_busy_error():
    """A timed-out lock acquisition raises UtecBleDeviceBusyError."""

    device = _device()
    holder_gate = asyncio.Event()
    _install_recording_stub(device, gate=holder_gate)

    def queue_holder():
        device._requests.append("holder-cmd")

    holder_task = asyncio.create_task(device.execute(queue_holder))
    await asyncio.sleep(0)
    assert device.is_busy is True

    with pytest.raises(UtecBleDeviceBusyError):
        await device.execute(lambda: None, timeout=0.01)

    holder_gate.set()
    await holder_task


@pytest.mark.asyncio
async def test_empty_queue_returns_false_without_sending():
    """A queue_commands that queues nothing skips send_requests entirely."""

    device = _device()
    send_called = False

    async def fake_send_requests() -> bool:
        nonlocal send_called
        send_called = True
        return True

    device.send_requests = fake_send_requests

    result = await device.execute(lambda: None)

    assert result is False
    assert send_called is False


@pytest.mark.asyncio
async def test_stale_requests_are_discarded_before_queueing():
    """Pre-existing junk in _requests is dropped, not sent alongside real ones."""

    device = _device()
    device._requests.append("stale-junk")
    sent = _install_recording_stub(device)

    def queue_real():
        device._requests.append("real-cmd")

    result = await device.execute(queue_real)

    assert result is True
    assert sent == [["real-cmd"]]


@pytest.mark.asyncio
async def test_lock_released_on_send_failure_and_next_execute_succeeds():
    """The lock is released even if send_requests raises."""

    device = _device()

    async def failing_send_requests() -> bool:
        device._requests.clear()
        raise RuntimeError("synthetic BLE failure")

    device.send_requests = failing_send_requests

    with pytest.raises(RuntimeError):
        await device.execute(lambda: device._requests.append("cmd"))

    assert device.is_busy is False

    sent = _install_recording_stub(device)
    result = await device.execute(lambda: device._requests.append("cmd-2"))

    assert result is True
    assert sent == [["cmd-2"]]


@pytest.mark.asyncio
async def test_is_busy_reflects_lock_state():
    """is_busy is False at rest and True while a command is in flight."""

    device = _device()
    assert device.is_busy is False

    gate = asyncio.Event()
    _install_recording_stub(device, gate=gate)

    def queue_cmd():
        device._requests.append("cmd")

    task = asyncio.create_task(device.execute(queue_cmd))
    await asyncio.sleep(0)

    assert device.is_busy is True

    gate.set()
    await task

    assert device.is_busy is False


@pytest.mark.asyncio
async def test_async_update_status_passes_skip_if_busy(enrolled_u_bolt):
    """The poll path is pinned to skip_if_busy=True so it never blocks."""

    ble_lock = UtecBleLock.from_enrollment(enrolled_u_bolt)

    captured_kwargs = {}

    async def fake_execute(queue_commands, **kwargs):
        captured_kwargs.update(kwargs)
        return False

    ble_lock.execute = fake_execute

    await ble_lock.async_update_status()

    assert captured_kwargs.get("skip_if_busy") is True
