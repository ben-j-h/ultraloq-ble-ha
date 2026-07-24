from ..enums import BLECommandCode, DeviceLockWorkMode
from ..util import to_byte_array
from .device import UtecBleDevice, UtecBleRequest


class UtecBleLock(UtecBleDevice):
    def __init__(
        self,
        uid: str,
        password: str,
        mac_uuid: str,
        device_name: str,
        wurx_uuid: str = "",
        device_model: str = "",
    ):
        super().__init__(
            uid=uid,
            password=password,
            mac_uuid=mac_uuid,
            wurx_uuid=wurx_uuid,
            device_name=device_name,
            device_model=device_model,
        )

    # Every method here queues through execute() so that queueing and sending
    # stay atomic against the status poll and against each other. Never call
    # add_request()/send_requests() directly from this class -- see
    # UtecBleDevice.execute().

    async def async_unlock(self, update: bool = True) -> bool:
        def queue():
            self.add_request(
                UtecBleRequest(
                    BLECommandCode.ADMIN_LOGIN, device=self, auth_required=True
                )
            )
            self.add_request(
                UtecBleRequest(BLECommandCode.UNLOCK, device=self, auth_required=True)
            )
            if update:
                self.add_request(UtecBleRequest(BLECommandCode.LOCK_STATUS))

        return await self.execute(queue)

    async def async_lock(self, update: bool = True) -> bool:
        def queue():
            self.add_request(
                UtecBleRequest(
                    BLECommandCode.ADMIN_LOGIN, device=self, auth_required=True
                )
            )
            self.add_request(
                UtecBleRequest(BLECommandCode.BOLT_LOCK, device=self, auth_required=True)
            )
            if update:
                self.add_request(UtecBleRequest(BLECommandCode.LOCK_STATUS))

        return await self.execute(queue)

    async def async_reboot(self) -> bool:
        def queue():
            self.add_request(UtecBleRequest(BLECommandCode.REBOOT))

        return await self.execute(queue)

    async def async_set_workmode(self, mode: DeviceLockWorkMode) -> bool:
        def queue():
            self.add_request(
                UtecBleRequest(
                    BLECommandCode.ADMIN_LOGIN, device=self, auth_required=True
                )
            )
            if self.capabilities.bt264:
                self.add_request(
                    UtecBleRequest(
                        BLECommandCode.SET_LOCK_STATUS, data=bytes([mode.value])
                    )
                )
            else:
                self.add_request(
                    UtecBleRequest(
                        BLECommandCode.SET_WORK_MODE, data=bytes([mode.value])
                    )
                )

        return await self.execute(queue)

    async def async_set_autolock(self, seconds: int) -> bool:
        # On a lock without autolock support this queues nothing, and execute()
        # returns False rather than raising "No commands to send."
        def queue():
            if self.capabilities.autolock:
                self.add_request(
                    UtecBleRequest(
                        BLECommandCode.ADMIN_LOGIN, device=self, auth_required=True
                    )
                )
                self.add_request(
                    UtecBleRequest(
                        BLECommandCode.SET_AUTOLOCK,
                        data=to_byte_array(seconds, 2) + bytes([0]),
                    )
                )

        return await self.execute(queue)

    async def async_update_status(self) -> bool:
        # A poll displaced by a user command is redundant: lock/unlock queue
        # LOCK_STATUS themselves. Skip rather than queue behind or raise.
        def queue():
            self.add_request(
                UtecBleRequest(
                    BLECommandCode.ADMIN_LOGIN, device=self, auth_required=True
                )
            )
            self.add_request(UtecBleRequest(BLECommandCode.LOCK_STATUS))
            if not self.capabilities.bt264:
                self.add_request(UtecBleRequest(BLECommandCode.GET_LOCK_STATUS))
                self.add_request(UtecBleRequest(BLECommandCode.GET_BATTERY))
                self.add_request(UtecBleRequest(BLECommandCode.GET_MUTE))

            if self.capabilities.autolock:
                self.add_request(UtecBleRequest(BLECommandCode.GET_AUTOLOCK))

        self.debug("Updating Ultraloq lock data")
        sent = await self.execute(queue, skip_if_busy=True)
        self.debug("Ultraloq lock update %s", "completed" if sent else "skipped")
        return sent
