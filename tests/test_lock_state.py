"""Non-physical tests for Home Assistant lock state transitions."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.exceptions import HomeAssistantError

from custom_components.ultraloq_ble.lock import RESYNC_ATTEMPTS, UtecLock
from custom_components.ultraloq_ble.utecio.ble.device import UtecBleDeviceError
from custom_components.ultraloq_ble.utecio.ble.lock import UtecBleLock
from custom_components.ultraloq_ble.utecio.enums import DeviceLockStatus


def _entity(enrolled_u_bolt):
    lock = UtecBleLock.from_enrollment(enrolled_u_bolt)
    return UtecLock(MagicMock(), lock, scan_interval=300, poll_offset=0)


def test_sync_state_clears_transitions(enrolled_u_bolt):
    """Confirmed protocol states clear optimistic transition flags."""

    entity = _entity(enrolled_u_bolt)
    entity._attr_is_locking = True
    entity.lock.lock_status = DeviceLockStatus.LOCKED.value
    entity._sync_state_from_lock()
    assert entity.is_locked is True
    assert entity.is_locking is False

    entity._attr_is_unlocking = True
    entity.lock.lock_status = DeviceLockStatus.UNLOCKED.value
    entity._sync_state_from_lock()
    assert entity.is_locked is False
    assert entity.is_unlocking is False


def test_autolock_due_requests_status_instead_of_inventing_state(
    enrolled_u_bolt,
):
    """An elapsed timer polls the lock and never asserts physical locking."""

    entity = _entity(enrolled_u_bolt)
    entity._attr_is_locked = False
    entity.request_update = MagicMock()

    entity._handle_autolock_due(None)

    assert entity.is_locked is False
    entity.request_update.assert_called_once_with()


@pytest.mark.asyncio
async def test_unlock_failure_propagates_to_home_assistant(enrolled_u_bolt):
    """A failed BLE write is visible to the service caller.

    The resync itself also fails every attempt here, exercising the full
    retry-then-give-up fallback path.
    """

    entity = _entity(enrolled_u_bolt)
    entity.lock.async_unlock = MagicMock(
        side_effect=UtecBleDeviceError("synthetic failure")
    )
    entity.lock.async_update_status = AsyncMock(
        side_effect=UtecBleDeviceError("resync also failed")
    )
    entity._schedule_transition_timeout = MagicMock()
    entity.async_write_ha_state = MagicMock()

    with patch("custom_components.ultraloq_ble.lock.asyncio.sleep", AsyncMock()):
        with pytest.raises(HomeAssistantError):
            await entity.async_unlock()

    assert entity.lock.async_update_status.call_count == RESYNC_ATTEMPTS


@pytest.mark.asyncio
async def test_unlock_failure_resync_retries_before_succeeding(enrolled_u_bolt):
    """A resync that fails on its first attempts still corrects state once
    a later attempt gets through -- a single flaky connection shouldn't be
    treated the same as sustained loss of connectivity to the lock.
    """

    entity = _entity(enrolled_u_bolt)
    entity.lock.lock_status = DeviceLockStatus.LOCKED.value
    entity._attr_is_locked = True

    calls = 0

    async def flaky_then_success():
        nonlocal calls
        calls += 1
        if calls < RESYNC_ATTEMPTS:
            raise UtecBleDeviceError("still flaky")
        entity.lock.lock_status = DeviceLockStatus.UNLOCKED.value
        return True

    entity.lock.async_unlock = MagicMock(
        side_effect=UtecBleDeviceError("synthetic write-ack failure")
    )
    entity.lock.async_update_status = AsyncMock(side_effect=flaky_then_success)
    entity._schedule_transition_timeout = MagicMock()
    entity.async_write_ha_state = MagicMock()

    with patch("custom_components.ultraloq_ble.lock.asyncio.sleep", AsyncMock()):
        with pytest.raises(HomeAssistantError):
            await entity.async_unlock()

    assert calls == RESYNC_ATTEMPTS
    assert entity.is_locked is False


@pytest.mark.asyncio
async def test_unlock_failure_resyncs_real_state(enrolled_u_bolt):
    """A failed write whose command still reached the lock corrects the
    displayed state instead of leaving it stale.

    Reproduces a state seen against real hardware: UNLOCK's local
    write-acknowledgement errored with no response, but the lock had already
    unlocked. A status re-query after the failure is what makes Home
    Assistant show the true state instead of stale 'locked'.
    """

    entity = _entity(enrolled_u_bolt)
    entity.lock.lock_status = DeviceLockStatus.LOCKED.value
    entity._attr_is_locked = True

    async def fake_update_status():
        entity.lock.lock_status = DeviceLockStatus.UNLOCKED.value
        return True

    entity.lock.async_unlock = MagicMock(
        side_effect=UtecBleDeviceError("synthetic write-ack failure")
    )
    entity.lock.async_update_status = AsyncMock(side_effect=fake_update_status)
    entity._schedule_transition_timeout = MagicMock()
    entity.async_write_ha_state = MagicMock()

    with pytest.raises(HomeAssistantError):
        await entity.async_unlock()

    assert entity.is_locked is False
