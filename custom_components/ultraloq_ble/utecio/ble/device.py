import asyncio
import datetime
import hashlib
import logging
import struct
from collections.abc import Awaitable, Callable
from typing import Any

from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak.exc import BleakError
from bleak_retry_connector import BleakNotFoundError, establish_connection, get_device
from Crypto.Cipher import AES
from ecdsa import SECP128r1, SigningKey
from ecdsa.ellipticcurve import Point

from ...const import (
    ENROLLMENT_ADDRESS,
    ENROLLMENT_ADMIN_PIN,
    ENROLLMENT_MODEL,
    ENROLLMENT_NAME,
    ENROLLMENT_UID,
    ENROLLMENT_WAKE_ADDRESS,
)
from .. import DeviceDefinition, GenericLock, known_devices, logger
from ..const import BATTERY_LEVEL, BOLT_STATUS, LOCK_MODE, CRC8Table
from ..enums import BLECommandCode, BleResponseCode, DeviceKeyUUID, DeviceServiceUUID
from ..util import bytes_to_int2, decode_password

RESPONSE_TIMEOUT_SECONDS = 15
# A full command cycle is ~5.7s; this only trips if the BLE stack has wedged.
COMMAND_LOCK_TIMEOUT_SECONDS = 60


class UtecBleNotFoundError(Exception):
    def __init__(self, message: str, detail: str | None = None) -> None:
        super().__init__(message)
        self.detail = detail

    def __str__(self) -> str:
        return f"{self.args[0]} {self.detail}" if self.detail else str(self.args[0])


class UtecBleError(Exception):
    def __init__(self, message: str, detail: str | None = None) -> None:
        super().__init__(message)
        self.detail = detail

    def __str__(self) -> str:
        return f"{self.args[0]} {self.detail}" if self.detail else str(self.args[0])


class UtecBleDeviceError(Exception):
    def __init__(self, message: str, detail: str | None = None) -> None:
        super().__init__(message)
        self.detail = detail

    def __str__(self) -> str:
        return f"{self.args[0]} {self.detail}" if self.detail else str(self.args[0])


class UtecBleDeviceBusyError(Exception):
    def __init__(self, message: str, detail: str | None = None) -> None:
        super().__init__(message)
        self.detail = detail

    def __str__(self) -> str:
        return f"{self.args[0]} {self.detail}" if self.detail else str(self.args[0])


class UtecBleDevice:
    def __init__(
        self,
        uid: str,
        password: str,
        mac_uuid: Any,
        device_name: str,
        wurx_uuid: Any = None,
        device_model: str = "",
        async_bledevice_callback: Callable[[str], Awaitable[BLEDevice | str]] = None,
        error_callback: Callable[[str, Exception], None] = None,
    ):
        self.mac_uuid = mac_uuid
        self.wurx_uuid = wurx_uuid
        self.uid = uid
        self.password: str = password
        self.name = device_name
        self.model: str = device_model
        self.capabilities: DeviceDefinition | Any = self._resolve_capabilities(
            device_model
        )
        self._requests: list[UtecBleRequest] = []
        # Response currently receiving notifications on the shared DATA
        # characteristic subscription held by send_requests().
        self._active_response: UtecBleResponse | None = None
        self.config: dict[str, Any]
        self.async_bledevice_callback = async_bledevice_callback
        self.error_callback = error_callback
        self.lock_status: int = -1
        self.lock_mode: int = -1
        self.autolock_time: int = -1
        self.battery: int = -1
        self.mute: bool = False
        self.bolt_status: int = -1
        self.sn: str = ""
        self.calendar: datetime.datetime
        # Serializes queue-then-send so concurrent callers cannot drain each
        # other's requests or cross-deliver notifications. See execute().
        self._command_lock = asyncio.Lock()
        self.device_time_offset: datetime.timedelta

    @property
    def is_busy(self) -> bool:
        """Whether a command sequence currently holds the device."""

        return self._command_lock.locked()

    @staticmethod
    def _resolve_capabilities(device_model: str) -> DeviceDefinition:
        """Return a capabilities instance for the provided model."""

        capabilities = known_devices.get(device_model)
        if isinstance(capabilities, DeviceDefinition):
            return capabilities
        if isinstance(capabilities, type) and issubclass(capabilities, DeviceDefinition):
            return capabilities()

        logger.warning("Unknown Ultraloq model from API: %s", device_model)
        return GenericLock()

    @classmethod
    def from_json(cls, json_config: dict[str, Any]):
        """Build a device from a legacy raw cloud record."""

        decoded_password = decode_password(json_config["user"]["password"])
        new_device = cls(
            device_name=json_config["name"],
            uid=str(json_config["user"]["uid"]),
            password=decoded_password,
            mac_uuid=json_config["uuid"],
            device_model=json_config["model"],
        )
        if json_config["params"]["extend_ble"]:
            new_device.wurx_uuid = json_config["params"]["extend_ble"]
        new_device.model = json_config["model"]
        new_device.config = json_config
        logger.debug("Loaded legacy Ultraloq metadata for model %s", new_device.model)

        return new_device

    @classmethod
    def from_enrollment(cls, enrollment: dict[str, Any]):
        """Build a device from minimized local enrollment metadata."""

        new_device = cls(
            device_name=enrollment[ENROLLMENT_NAME],
            uid=enrollment[ENROLLMENT_UID],
            password=enrollment[ENROLLMENT_ADMIN_PIN],
            mac_uuid=enrollment[ENROLLMENT_ADDRESS],
            wurx_uuid=enrollment.get(ENROLLMENT_WAKE_ADDRESS, ""),
            device_model=enrollment[ENROLLMENT_MODEL],
        )
        new_device.config = {}
        logger.debug("Loaded Ultraloq enrollment for model %s", new_device.model)

        return new_device

    async def async_update_status(self):
        pass

    def error(self, e: Exception, note: str = "") -> Exception:
        if note:
            e.add_note(note)

        if self.error_callback:
            self.error_callback(e)

        self.debug("Ultraloq BLE operation failed (%s): %s", type(e).__name__, e)
        return e

    def debug(self, msg: object, *args: object):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(msg, *args)

    def add_request(self, request: "UtecBleRequest", priority: bool = False):
        request.device = self
        request.ensure_auth()
        if priority:
            self._requests.insert(0, request)
        else:
            self._requests.append(request)

    async def execute(
        self,
        queue_commands: Callable[[], None],
        *,
        skip_if_busy: bool = False,
        timeout: float = COMMAND_LOCK_TIMEOUT_SECONDS,
    ) -> bool:
        """Queue a command sequence and send it, exclusively.

        `_requests` is shared device state and send_requests() drains all of it,
        so queueing and sending must be atomic. If two callers interleave, the
        first drains both sets of commands and the second finds an empty queue.
        Holding the mutex across both halves is what prevents that, which is why
        callers pass a closure instead of queueing themselves.

        `skip_if_busy` is for callers whose work is redundant if something else
        already holds the device -- a status poll displaced by a user command is
        not a failure worth raising. User commands wait instead; a dropped
        unlock is never acceptable.

        Returns True if commands were sent, False if the sequence was skipped or
        queued nothing.
        """

        if skip_if_busy and self._command_lock.locked():
            self.debug("Skipping Ultraloq request sequence; device is busy")
            return False

        try:
            await asyncio.wait_for(self._command_lock.acquire(), timeout)
        except TimeoutError:
            raise self.error(
                UtecBleDeviceBusyError(
                    "Unable to process Ultraloq requests.",
                    f"Device stayed busy for more than {timeout:g}s.",
                )
            ) from None

        try:
            # Any leftovers here mean an earlier caller queued and then failed
            # before sending. Sending its commands now would be wrong.
            if self._requests:
                self.debug(
                    "Discarding %d stale Ultraloq request(s)", len(self._requests)
                )
                self._requests.clear()

            queue_commands()

            if not self._requests:
                self.debug("No Ultraloq commands queued; nothing to send")
                return False

            return await self.send_requests()
        finally:
            self._command_lock.release()

    async def send_requests(self) -> bool:
        client: BleakClient = None
        notifications_started = False
        try:
            if len(self._requests) < 1:
                raise self.error(
                    UtecBleError(
                        "Unable to process Ultraloq requests.",
                        "No commands to send.",
                    )
                )

            try:
                if not (device := await self._get_bledevice(self.mac_uuid)):
                    raise BleakNotFoundError()
                client = await establish_connection(
                    client_class=BleakClient,
                    device=device,
                    name="Ultraloq lock",
                    max_attempts=1 if self.wurx_uuid else 2,
                    ble_device_callback=self._brc_get_lock_device,
                )
            except (BleakNotFoundError, BleakError, TimeoutError) as first_err:
                try:
                    if not self.wurx_uuid:
                        raise

                    await self.async_wakeup_device()
                    if not (device := await self._get_bledevice(self.mac_uuid)):
                        raise BleakNotFoundError("Wakeup device not found.")

                    client = await establish_connection(
                        client_class=BleakClient,
                        device=device,
                        name="Ultraloq lock",
                        max_attempts=2,
                        ble_device_callback=self._brc_get_lock_device,
                    )
                except (BleakError, BleakNotFoundError, TimeoutError) as second_err:
                    raise self.error(
                        UtecBleNotFoundError(
                            "Could not connect to the Ultraloq lock.",
                            (
                                "Connection failed after direct and wake-up attempts. "
                                f"Direct error: {type(first_err).__name__}. "
                                f"Wake-up error: {type(second_err).__name__}."
                            ),
                        )
                    ) from None

            try:
                aes_key = await UtecBleDeviceKey.get_shared_key(
                    client=client, device=self
                )
            except Exception:
                raise self.error(
                    UtecBleDeviceError(
                        "Error communicating with the Ultraloq lock.",
                        "Could not retrieve shared key.",
                    )
                ) from None

            # Subscribe once for the whole connection and route each notification
            # to the request currently in flight.
            #
            # Previously every request called start_notify/stop_notify on the same
            # DATA characteristic. Completed requests stayed attached, so a single
            # unlock had every earlier response object re-parsing every later
            # notification. It also cost two extra GATT round trips per request.
            async def _dispatch_notification(sender, data):
                response = self._active_response
                if response is not None:
                    await response._receive_write_response(sender, data)

            self._active_response = None
            await client.start_notify(
                DeviceServiceUUID.DATA.value, _dispatch_notification
            )
            notifications_started = True

            for request in self._requests[:]:
                if not request.sent or not request.response.completed:
                    request.aes_key = aes_key
                    request.device = self
                    request.sent = True
                    try:
                        await request._get_response(client)
                        self._requests.remove(request)
                    except (
                        UtecBleDeviceError,
                        UtecBleDeviceBusyError,
                        UtecBleNotFoundError,
                        UtecBleError,
                    ):
                        # _get_response() already logs and raises a specific,
                        # secret-free error (timed out vs. rejected vs.
                        # transport failure); let it propagate instead of
                        # collapsing it into a generic "Command X failed" that
                        # hides which one it was.
                        raise
                    except Exception as err:
                        # Anything not already in our error hierarchy (e.g. a
                        # raw BleakError) must still be wrapped, or callers
                        # that only catch Utec* exceptions see it escape
                        # unhandled. GATT/transport error text is protocol
                        # diagnostics, not a secret, so keep it.
                        raise self.error(
                            UtecBleDeviceError(
                                "Error communicating with the Ultraloq lock.",
                                f"Command {request.command.name} failed ({err}).",
                            )
                        ) from None

            # Reaching here means every queued command got a response. Without
            # this the declared "-> bool" was always None, so neither callers
            # nor execute() could tell success from a skipped sequence.
            return True

        except Exception:  # unhandled
            raise

        finally:
            self._requests.clear()
            self._active_response = None
            if client:
                if notifications_started:
                    try:
                        await client.stop_notify(DeviceServiceUUID.DATA.value)
                    except Exception as err:
                        logger.debug(
                            "Failed to stop Ultraloq notifications (%s)",
                            type(err).__name__,
                        )
                try:
                    await client.disconnect()
                except TimeoutError as err:
                    logger.warning(
                        "Timed out while disconnecting from an Ultraloq lock (%s)",
                        type(err).__name__,
                    )
                except Exception as err:
                    logger.warning(
                        "Unexpected error while disconnecting from an Ultraloq lock (%s)",
                        type(err).__name__,
                    )

    async def _get_bledevice(self, address: str) -> BLEDevice:
        device = (
            await self.async_bledevice_callback(address)
            if self.async_bledevice_callback
            else await get_device(address)
        )
        return device

    async def _brc_get_lock_device(self) -> BLEDevice:
        return await self._get_bledevice(self.mac_uuid)

    async def _brc_get_wurx_device(self) -> BLEDevice:
        return await self._get_bledevice(self.wurx_uuid)

    async def async_wakeup_device(self):
        if not (device := await self._get_bledevice(self.wurx_uuid)):
            raise BleakNotFoundError()

        wclient: BleakClient = await establish_connection(
            client_class=BleakClient,
            device=device,
            name="Ultraloq wake receiver",
            max_attempts=2,
            ble_device_callback=self._brc_get_wurx_device,
        )
        self.debug("Ultraloq wake-up receiver connected")
        try:
            await wclient.disconnect()
        except TimeoutError as err:
            logger.warning(
                "Timed out while disconnecting an Ultraloq wake receiver (%s)",
                type(err).__name__,
            )
        except Exception as err:
            logger.warning(
                "Unexpected error while disconnecting an Ultraloq wake receiver (%s)",
                type(err).__name__,
            )


class UtecBleRequest:
    def __init__(
        self,
        command: BLECommandCode,
        device: UtecBleDevice = None,
        data: bytes = b"",
        auth_required: bool = False,
    ):
        if command in {
            BLECommandCode.ADMIN_LOGIN,
            BLECommandCode.UNLOCK,
            BLECommandCode.BOLT_LOCK,
            BLECommandCode.SET_LOCK_STATUS,
            BLECommandCode.SET_AUTOLOCK,
            BLECommandCode.SET_WORK_MODE,
        }:
            auth_required = True

        self.command = command
        self.device = device
        self.uuid = DeviceServiceUUID.DATA.value
        self.response: UtecBleResponse
        self.aes_key: bytes
        self.sent = False
        self.data = data
        self.auth_required = auth_required
        self._auth_appended = False
        self._build_packet()

    def ensure_auth(self) -> None:
        """Attach auth bytes once the request has a device reference."""

        if not self.auth_required or self._auth_appended:
            return
        if self.device is None:
            raise ValueError(f"Device is required for auth command {self.command.name}")

        self._build_packet()

    def _build_packet(self) -> None:
        """Build the current request buffer from scratch."""

        self._auth_appended = False
        self.buffer = bytearray(5120)
        self.buffer[0] = 0x7F
        byte_array = bytearray(int.to_bytes(2, 2, "little"))
        self.buffer[1] = byte_array[0]
        self.buffer[2] = byte_array[1]
        self.buffer[3] = self.command.value
        self._write_pos = 4

        if self.auth_required and self.device is not None:
            self._append_auth(self.device.uid, self.device.password)
        if self.data:
            self._append_data(self.data)
        self._append_length()
        self._append_crc()

    def _append_data(self, data):
        data_len = len(data)
        self.buffer[self._write_pos : self._write_pos + data_len] = data
        self._write_pos += data_len

    def _append_auth(self, uid: str, password: str = ""):
        logger.debug("Building authenticated payload for %s", self.command.name)
        if uid:
            byte_array = bytearray(int(uid).to_bytes(4, "little"))
            self.buffer[self._write_pos : self._write_pos + 4] = byte_array
            self._write_pos += 4
        if password:
            byte_array = bytearray(int(password).to_bytes(4, "little"))
            byte_array[3] = (len(password) << 4) | byte_array[3]
            self.buffer[self._write_pos : self._write_pos + 4] = byte_array[:4]
            self._write_pos += 4
        self._auth_appended = True

    def _append_length(self):
        byte_array = bytearray(int(self._write_pos - 2).to_bytes(2, "little"))
        self.buffer[1] = byte_array[0]
        self.buffer[2] = byte_array[1]

    def _append_crc(self):
        b = 0
        for i2 in range(3, self._write_pos):
            m_index = (b ^ self.buffer[i2]) & 0xFF
            b = CRC8Table[m_index]

        self.buffer[self._write_pos] = b
        self._write_pos += 1

    @property
    def package(self) -> bytearray:
        return self.buffer[: self._write_pos]

    def encrypted_package(self, aes_key: bytes):
        bArr2 = bytearray(self._write_pos)
        bArr2[: self._write_pos] = self.buffer[: self._write_pos]
        num_chunks = (self._write_pos // 16) + (1 if self._write_pos % 16 > 0 else 0)
        pkg = bytearray(num_chunks * 16)

        i2 = 0
        while i2 < num_chunks:
            i3 = i2 + 1
            if i3 < num_chunks:
                bArr = bArr2[i2 * 16 : (i2 + 1) * 16]
            else:
                i4 = self._write_pos - ((num_chunks - 1) * 16)
                bArr = bArr2[i2 * 16 : i2 * 16 + i4]

            initialValue = bytearray(16)
            encrypt_buffer = bytearray(16)
            encrypt_buffer[: len(bArr)] = bArr
            cipher = AES.new(aes_key, AES.MODE_CBC, initialValue)
            encrypt = cipher.encrypt(encrypt_buffer)
            if encrypt is None:
                encrypt = bytearray(16)

            pkg[i2 * 16 : (i2 + 1) * 16] = encrypt
            i2 = i3
        return pkg

    async def _get_response(self, client: BleakClient):
        self.response = UtecBleResponse(self, self.device)
        try:
            logger.debug("Sending Ultraloq command %s", self.command.name)
            # send_requests() holds a single subscription for the connection and
            # dispatches to whichever response is active, so only claim it here.
            self.device._active_response = self.response
            try:
                await client.write_gatt_char(
                    self.uuid, self.encrypted_package(self.aes_key)
                )
            except Exception as write_err:
                # The write-acknowledgement transaction (esp. relayed through
                # a Bluetooth proxy) can fail at the transport layer after the
                # lock has already processed the command and sent back a
                # valid notification -- the notify callback runs concurrently
                # with this await, not nested inside it. Only treat this as a
                # real failure if no response has arrived yet; otherwise the
                # write error is stale and the command already succeeded.
                if not self.response.completed:
                    raise
                logger.debug(
                    "Ignoring write-acknowledgement error for %s"
                    " (%s); a valid response already arrived",
                    self.command.name,
                    type(write_err).__name__,
                )
            try:
                await asyncio.wait_for(
                    self.response.response_completed.wait(),
                    timeout=RESPONSE_TIMEOUT_SECONDS,
                )
            except TimeoutError as err:
                raise self.device.error(
                    UtecBleDeviceError(
                        "Error communicating with the Ultraloq lock.",
                        (
                            f"Timed out waiting {RESPONSE_TIMEOUT_SECONDS} seconds "
                            f"for {self.command.name} response."
                        ),
                    )
                ) from err
            if (
                self.command
                in {
                    BLECommandCode.ADMIN_LOGIN,
                    BLECommandCode.UNLOCK,
                    BLECommandCode.BOLT_LOCK,
                    BLECommandCode.SET_LOCK_STATUS,
                    BLECommandCode.SET_AUTOLOCK,
                    BLECommandCode.SET_WORK_MODE,
                }
                and not self.response.success
            ):
                raise self.device.error(
                    UtecBleDeviceError(
                        "Error communicating with the Ultraloq lock.",
                        f"Command {self.command.name} was rejected by the lock.",
                    )
                )
        except Exception as e:
            raise self.device.error(e)
        finally:
            # Stop routing notifications to this response; the connection-wide
            # subscription is torn down by send_requests().
            if self.device._active_response is self.response:
                self.device._active_response = None


class UtecBleResponse:
    def __init__(self, request: UtecBleRequest, device: UtecBleDevice):
        self.buffer = bytearray()
        self.request = request
        self.response_completed = asyncio.Event()
        self.device = device

    async def _receive_write_response(
        self, sender: BleakGATTCharacteristic, data: bytearray
    ):
        try:
            logger.debug(
                "Received Ultraloq notification chunk for %s (%s bytes)",
                self.request.command.name,
                len(data),
            )
            self._append(data, bytearray(self.request.aes_key))
            if self.completed and self.is_valid:
                await self._read_response()
                self.response_completed.set()
        except Exception as e:
            e.add_note("Error receiving an Ultraloq write response.")
            raise self.device.error(e)

    def reset(self):
        self.buffer = bytearray(0)

    def _append(self, barr: bytearray, aes_key: bytearray):
        f495iv = bytearray(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, f495iv)
        output = cipher.decrypt(barr)

        if (self.length > 0 and self.buffer[0] == 0x7F) or output[0] == 0x7F:
            self.buffer += output

    def _parameter(self, index):
        data_len = self.data_len
        if data_len < 3:
            return None

        param_size = (data_len - 2) - index
        bArr2 = bytearray([0] * param_size)
        bArr2[:] = self.buffer[index + 4 : index + 4 + param_size]

        return bytearray(bArr2)

    @property
    def is_valid(self):
        cmd = self.command
        return (
            True
            if (self.completed and cmd and isinstance(cmd, BleResponseCode))
            else False
        )

    @property
    def completed(self):
        return True if self.length > 3 and self.length >= self.package_len else False

    @property
    def length(self):
        return len(self.buffer)

    @property
    def data_len(self):
        return (
            int.from_bytes(self.buffer[1:3], byteorder="little")
            if self.length > 3
            else 0
        )

    @property
    def package_len(self):
        return self.data_len + 4 if self.length > 3 else 0

    @property
    def package(self):
        return self.buffer[: self.package_len - 1]

    @property
    def command(self) -> BleResponseCode | Any:
        if not self.completed:
            return None
        try:
            return BleResponseCode(self.buffer[3])
        except ValueError:
            return None

    @property
    def success(self) -> bool:
        return self.completed and self.length > 4 and self.buffer[4] == 0

    @property
    def data(self) -> bytearray:
        if self.is_valid:
            return self.buffer[5 : self.data_len + 5]
        else:
            return bytearray()

    async def _read_response(self):
        try:
            logger.debug(
                "Parsed Ultraloq response cmd=%s success=%s",
                self.command.name,
                self.success,
            )
            if not self.success:
                logger.warning(
                    "Ultraloq lock reported failure for %s", self.command.name
                )

            if self.command == BleResponseCode.GET_LOCK_STATUS:
                self.device.lock_mode = int(self.data[0])
                self.device.bolt_status = int(self.data[1])
                self.device.debug(
                    "Lock mode=%s (%s), bolt status=%s (%s)",
                    self.device.lock_mode,
                    LOCK_MODE[self.device.lock_mode],
                    self.device.bolt_status,
                    BOLT_STATUS[self.device.bolt_status],
                )

            elif self.command == BleResponseCode.SET_LOCK_STATUS:
                self.device.lock_mode = self.data[0]
                self.device.debug("Work mode=%s", self.device.lock_mode)

            elif self.command == BleResponseCode.GET_BATTERY:
                self.device.battery = int(self.data[0])
                self.device.debug(
                    "Battery level=%s (%s)",
                    self.device.battery,
                    BATTERY_LEVEL[self.device.battery],
                )

            elif self.command == BleResponseCode.GET_AUTOLOCK:
                self.device.autolock_time = bytes_to_int2(self.data[:2])
                self.device.debug("Auto-lock time=%s", self.device.autolock_time)

            elif self.command == BleResponseCode.SET_AUTOLOCK:
                if self.success:
                    self.device.autolock_time = bytes_to_int2(self.data[:2])
                    self.device.debug("Auto-lock time=%s", self.device.autolock_time)

            elif self.command == BleResponseCode.GET_BATTERY:
                self.device.battery = int(self.data[0])
                self.device.debug(
                    "Battery level=%s (%s)",
                    self.device.battery,
                    BATTERY_LEVEL[self.device.battery],
                )

            elif self.command == BleResponseCode.GET_SN:
                self.device.sn = self.data.decode("ISO8859-1")
                self.device.debug("Serial number read successfully")

            elif self.command == BleResponseCode.GET_MUTE:
                self.device.mute = bool(self.data[0])
                self.device.debug("Mute=%s", self.device.mute)

            elif self.command == BleResponseCode.SET_WORK_MODE:
                if self.success:
                    self.device.lock_mode = self.data[0]
                    self.device.debug("Work mode=%s", self.device.lock_mode)

            elif self.command == BleResponseCode.UNLOCK:
                self.device.debug("Unlock command completed")

            elif self.command == BleResponseCode.BOLT_LOCK:
                self.device.debug("Lock command completed")

            elif self.command == BleResponseCode.LOCK_STATUS:
                self.device.lock_status = int(self.data[0])
                self.device.bolt_status = int(self.data[1])
                self.device.debug(
                    "Lock status=%s, bolt status=%s",
                    self.device.lock_status,
                    self.device.bolt_status,
                )
                if self.length > 16:
                    self.device.battery = int(self.data[2])
                    self.device.lock_mode = int(self.data[3])
                    self.device.mute = bool(self.data[4])
                    self.device.debug(
                        "Battery level=%s, mute=%s, mode=%s",
                        self.device.battery,
                        self.device.mute,
                        self.device.lock_mode,
                    )

            self.device.debug("Command completed: %s", self.command.name)

        except Exception as e:
            raise self.device.error(
                UtecBleDeviceError(
                    "Error updating Ultraloq lock data.",
                    f"While handling {self.command.name}: {type(e).__name__}",
                )
            )


class UtecBleDeviceKey:
    @staticmethod
    async def get_shared_key(client: BleakClient, device: UtecBleDevice) -> bytes:
        if client.services.get_characteristic(DeviceKeyUUID.STATIC.value):
            device.debug("Using STATIC key exchange")
            secret = await client.read_gatt_char(DeviceKeyUUID.STATIC.value)
            return bytearray(b"Anviz.ut") + secret
        elif client.services.get_characteristic(DeviceKeyUUID.MD5.value):
            device.debug("Using MD5 key exchange")
            return await UtecBleDeviceKey.get_md5_key(client, device)
        elif client.services.get_characteristic(DeviceKeyUUID.ECC.value):
            device.debug("Using ECC key exchange")
            return await UtecBleDeviceKey.get_ecc_key(client, device)
        else:
            raise NotImplementedError("Unknown Ultraloq encryption method.")

    @staticmethod
    async def get_ecc_key(client: BleakClient, device: UtecBleDevice) -> bytes:
        try:
            private_key = SigningKey.generate(curve=SECP128r1)
            received_pubkey = []
            public_key = private_key.get_verifying_key()  # type: ignore # noqa
            pub_x = public_key.pubkey.point.x().to_bytes(16, "little")  # type: ignore # noqa
            pub_y = public_key.pubkey.point.y().to_bytes(16, "little")  # type: ignore # noqa

            notification_event = asyncio.Event()

            def notification_handler(sender, data):
                device.debug("Received ECC notification chunk")
                received_pubkey.append(data)
                if len(received_pubkey) == 2:
                    notification_event.set()

            device.debug("Starting ECC key exchange")
            await client.start_notify(DeviceKeyUUID.ECC.value, notification_handler)
            await client.write_gatt_char(DeviceKeyUUID.ECC.value, pub_x)
            await client.write_gatt_char(DeviceKeyUUID.ECC.value, pub_y)
            device.debug("Waiting for ECC key response")
            await notification_event.wait()

            await client.stop_notify(DeviceKeyUUID.ECC.value)
            device.debug("Received ECC public key")

            # The lock generates an ephemeral keypair per session -- three
            # consecutive handshakes produced three different public keys -- so
            # the ~2.3s spent waiting for this key cannot be cached away.
            rec_key_point = Point(
                SECP128r1.curve,
                int.from_bytes(received_pubkey[0], "little"),
                int.from_bytes(received_pubkey[1], "little"),
            )
            shared_point = private_key.privkey.secret_multiplier * rec_key_point  # type: ignore # noqa
            shared_key = int.to_bytes(shared_point.x(), 16, "little")
            device.debug("ECC shared key established")
            return shared_key
        except Exception as e:
            e.add_note("Failed to update the Ultraloq ECC key.")
            raise device.error(e)

    @staticmethod
    async def get_md5_key(client: BleakClient, device: UtecBleDevice) -> bytes:
        try:
            secret = await client.read_gatt_char(DeviceKeyUUID.MD5.value)

            if len(secret) != 16:
                raise device.error(
                    ValueError("Expected an Ultraloq secret of length 16.")
                )

            part1 = struct.unpack("<Q", secret[:8])[0]  # Little-endian
            part2 = struct.unpack("<Q", secret[8:])[0]

            xor_val1 = (
                part1 ^ 0x716F6C6172744C55
            )  # this value corresponds to 'ULtraloq' in little-endian
            xor_val2_part1 = (part2 >> 56) ^ (part1 >> 56) ^ 0x71
            xor_val2_part2 = ((part2 >> 48) & 0xFF) ^ ((part1 >> 48) & 0xFF) ^ 0x6F
            xor_val2_part3 = ((part2 >> 40) & 0xFF) ^ ((part1 >> 40) & 0xFF) ^ 0x6C
            xor_val2_part4 = ((part2 >> 32) & 0xFF) ^ ((part1 >> 32) & 0xFF) ^ 0x61
            xor_val2_part5 = ((part2 >> 24) & 0xFF) ^ ((part1 >> 24) & 0xFF) ^ 0x72
            xor_val2_part6 = ((part2 >> 16) & 0xFF) ^ ((part1 >> 16) & 0xFF) ^ 0x74
            xor_val2_part7 = ((part2 >> 8) & 0xFF) ^ ((part1 >> 8) & 0xFF) ^ 0x4C
            xor_val2_part8 = (part2 & 0xFF) ^ (part1 & 0xFF) ^ 0x55

            xor_val2 = (
                (xor_val2_part1 << 56)
                | (xor_val2_part2 << 48)
                | (xor_val2_part3 << 40)
                | (xor_val2_part4 << 32)
                | (xor_val2_part5 << 24)
                | (xor_val2_part6 << 16)
                | (xor_val2_part7 << 8)
                | xor_val2_part8
            )

            xor_result = struct.pack("<QQ", xor_val1, xor_val2)

            m = hashlib.md5()
            m.update(xor_result)
            result = m.digest()

            bVar2 = (part1 & 0xFF) ^ 0x55
            if bVar2 & 1:
                m = hashlib.md5()
                m.update(result)
                result = m.digest()

            device.debug("MD5 shared key established")
            return result

        except Exception as e:
            e.add_note("Failed to update the Ultraloq MD5 key.")
            raise device.error(e)
