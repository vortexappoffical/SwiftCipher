from __future__ import annotations

import enum
import json
import time
import secrets
from abc import ABC, abstractmethod
from typing import (
    Any, FrozenSet, List, Mapping, NamedTuple, Optional, Set, Tuple, Type, TypeVar, Union, cast
)
from typing_extensions import Annotated, assert_never, TypeAlias

import xeddsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import BaseModel
from pydantic.functional_serializers import PlainSerializer
from pydantic.functional_validators import PlainValidator



################
# Type Aliases #
################

JSONType: TypeAlias = Union[Mapping[str, "JSONType"], List["JSONType"], str, int, float, bool, None]
JSONObject: TypeAlias = Mapping[str, "JSONType"]

############################
# Structures (NamedTuples) #
############################

class Bundle(NamedTuple):
    identity_key: bytes
    signed_pre_key: bytes
    signed_pre_key_sig: bytes
    pre_keys: FrozenSet[bytes]

class Header(NamedTuple):
    identity_key: bytes
    ephemeral_key: bytes
    signed_pre_key: bytes
    pre_key: Optional[bytes]

################
# Enumerations #
################

@enum.unique
class IdentityKeyFormat(enum.Enum):
    CURVE_25519 = "CURVE_25519"
    ED_25519 = "ED_25519"

@enum.unique
class SecretType(enum.Enum):
    SEED = "SEED"
    PRIV = "PRIV"

# ---- x3dh/crypto_provider.py ----

@enum.unique
class HashFunction(enum.Enum):
    SHA_256 = "SHA_256"
    SHA_512 = "SHA_512"

    @property
    def hash_size(self) -> int:
        if self is HashFunction.SHA_256:
            return 32
        if self is HashFunction.SHA_512:
            return 64
        return assert_never(self)

class CryptoProvider(ABC):
    @staticmethod
    @abstractmethod
    async def hkdf_derive(
        hash_function: HashFunction,
        length: int,
        salt: bytes,
        info: bytes,
        key_material: bytes
    ) -> bytes:
        pass

# ---- x3dh/crypto_provider_cryptography.py ----

def get_hash_algorithm(hash_function: HashFunction) -> hashes.HashAlgorithm:
    if hash_function is HashFunction.SHA_256:
        return hashes.SHA256()
    if hash_function is HashFunction.SHA_512:
        return hashes.SHA512()
    return assert_never(hash_function)

class CryptoProviderImpl(CryptoProvider):
    @staticmethod
    async def hkdf_derive(
        hash_function: HashFunction,
        length: int,
        salt: bytes,
        info: bytes,
        key_material: bytes
    ) -> bytes:
        return HKDF(
            algorithm=get_hash_algorithm(hash_function),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend()
        ).derive(key_material)

# ---- x3dh/models.py ----

def _json_bytes_decoder(val: Any) -> bytes:
    if isinstance(val, bytes):
        return val
    if isinstance(val, str):
        return bytes(map(ord, val))
    raise ValueError("bytes fields must be encoded as bytes or str.")

def _json_bytes_encoder(val: bytes) -> str:
    return "".join(map(chr, val))

JsonBytes = Annotated[bytes, PlainValidator(_json_bytes_decoder), PlainSerializer(_json_bytes_encoder)]

class IdentityKeyPairModel(BaseModel):
    version: str = "1.0.0"
    secret: JsonBytes
    secret_type: SecretType

class SignedPreKeyPairModel(BaseModel):
    version: str = "1.0.0"
    priv: JsonBytes
    sig: JsonBytes
    timestamp: int

class BaseStateModel(BaseModel):
    version: str = "1.0.0"
    identity_key: IdentityKeyPairModel
    signed_pre_key: SignedPreKeyPairModel
    old_signed_pre_key: Optional[SignedPreKeyPairModel]
    pre_keys: FrozenSet[JsonBytes]

# ---- x3dh/migrations.py ----

class PreStableKeyPairModel(BaseModel):
    priv: str
    pub: str

class PreStableSignedPreKeyModel(BaseModel):
    key: PreStableKeyPairModel
    signature: str
    timestamp: float

class PreStableModel(BaseModel):
    changed: bool
    ik: PreStableKeyPairModel
    spk: PreStableSignedPreKeyModel
    otpks: List[PreStableKeyPairModel]

def parse_identity_key_pair_model(serialized: JSONObject) -> IdentityKeyPairModel:
    version = cast(str, serialized["version"])
    model: BaseModel = {
        "1.0.0": IdentityKeyPairModel,
        "1.0.1": IdentityKeyPairModel
    }[version](**serialized)  # type: ignore[arg-type]
    assert isinstance(model, IdentityKeyPairModel)
    return model

def parse_signed_pre_key_pair_model(serialized: JSONObject) -> SignedPreKeyPairModel:
    version = cast(str, serialized["version"])
    model: BaseModel = {
        "1.0.0": SignedPreKeyPairModel,
        "1.0.1": SignedPreKeyPairModel
    }[version](**serialized)  # type: ignore[arg-type]
    assert isinstance(model, SignedPreKeyPairModel)
    return model

def parse_base_state_model(serialized: JSONObject) -> Tuple[BaseStateModel, bool]:
    bundle_needs_publish = False
    version = cast(str, serialized["version"]) if "version" in serialized else None
    model: BaseModel = {
        None: PreStableModel,
        "1.0.0": BaseStateModel,
        "1.0.1": BaseStateModel
    }[version](**serialized)
    if isinstance(model, PreStableModel):
        bundle_needs_publish = bundle_needs_publish or model.changed
        model = BaseStateModel(
            identity_key=IdentityKeyPairModel(
                secret=base64.b64decode(model.ik.priv),
                secret_type=SecretType.PRIV
            ),
            signed_pre_key=SignedPreKeyPairModel(
                priv=base64.b64decode(model.spk.key.priv),
                sig=base64.b64decode(model.spk.signature),
                timestamp=int(model.spk.timestamp)
            ),
            old_signed_pre_key=None,
            pre_keys=frozenset({ base64.b64decode(pre_key.priv) for pre_key in model.otpks })
        )
    assert isinstance(model, BaseStateModel)
    return model, bundle_needs_publish

# ---- x3dh/pre_key_pair.py ----

class PreKeyPair(NamedTuple):
    priv: bytes
    @property
    def pub(self) -> bytes:
        return xeddsa.priv_to_curve25519_pub(self.priv)

# ---- x3dh/signed_pre_key_pair.py ----

class SignedPreKeyPair(NamedTuple):
    priv: bytes
    sig: bytes
    timestamp: int

    @property
    def pub(self) -> bytes:
        return xeddsa.priv_to_curve25519_pub(self.priv)

    @property
    def model(self) -> SignedPreKeyPairModel:
        return SignedPreKeyPairModel(priv=self.priv, sig=self.sig, timestamp=self.timestamp)

    @property
    def json(self) -> JSONObject:
        return cast(JSONObject, json.loads(self.model.json()))

    @staticmethod
    def from_model(model: SignedPreKeyPairModel) -> "SignedPreKeyPair":
        return SignedPreKeyPair(priv=model.priv, sig=model.sig, timestamp=model.timestamp)

    @staticmethod
    def from_json(serialized: JSONObject) -> "SignedPreKeyPair":
        return SignedPreKeyPair.from_model(parse_signed_pre_key_pair_model(serialized))

# ---- x3dh/identity_key_pair.py ----

class IdentityKeyPair(ABC):
    @property
    def model(self) -> IdentityKeyPairModel:
        return IdentityKeyPairModel(secret=self.secret, secret_type=self.secret_type)

    @property
    def json(self) -> JSONObject:
        return cast(JSONObject, json.loads(self.model.json()))

    @staticmethod
    def from_model(model: IdentityKeyPairModel) -> "IdentityKeyPair":
        if model.secret_type is SecretType.PRIV:
            return IdentityKeyPairPriv(model.secret)
        if model.secret_type is SecretType.SEED:
            return IdentityKeyPairSeed(model.secret)
        return assert_never(model.secret_type)

    @staticmethod
    def from_json(serialized: JSONObject) -> "IdentityKeyPair":
        return IdentityKeyPair.from_model(parse_identity_key_pair_model(serialized))

    @property
    @abstractmethod
    def secret_type(self) -> SecretType:
        pass

    @property
    @abstractmethod
    def secret(self) -> bytes:
        pass

    @abstractmethod
    def as_priv(self) -> "IdentityKeyPairPriv":
        pass




class IdentityKeyPairPriv(IdentityKeyPair):
    def __init__(self, priv: bytes) -> None:
        if len(priv) != 32:
            raise ValueError("Expected the private key to be 32 bytes long.")
        self.__priv = priv

    @property
    def secret_type(self) -> SecretType:
        return SecretType.PRIV

    @property
    def secret(self) -> bytes:
        return self.priv

    def as_priv(self) -> "IdentityKeyPairPriv":
        return self

    @property
    def priv(self) -> bytes:
        return self.__priv

class IdentityKeyPairSeed(IdentityKeyPair):
    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError("Expected the seed to be 32 bytes long.")
        self.__seed = seed

    @property
    def secret_type(self) -> SecretType:
        return SecretType.SEED

    @property
    def secret(self) -> bytes:
        return self.seed

    def as_priv(self) -> "IdentityKeyPairPriv":
        return IdentityKeyPairPriv(xeddsa.seed_to_priv(self.__seed))

    @property
    def seed(self) -> bytes:
        return self.__seed

# ---- x3dh/base_state.py ----

class KeyAgreementException(Exception):
    pass

BaseStateTypeT = TypeVar("BaseStateTypeT", bound="BaseState")

class BaseState(ABC):
    def __init__(self) -> None:
        self.__identity_key_format: IdentityKeyFormat
        self.__hash_function: HashFunction
        self.__info: bytes
        self.__identity_key: IdentityKeyPair
        self.__signed_pre_key: SignedPreKeyPair
        self.__old_signed_pre_key: Optional[SignedPreKeyPair]
        self.__pre_keys: Set[PreKeyPair]
        self.__hidden_pre_keys: Set[PreKeyPair]

    @classmethod
    def create(
        cls: Type[BaseStateTypeT],
        identity_key_format: IdentityKeyFormat,
        hash_function: HashFunction,
        info: bytes,
        identity_key_pair: Optional[IdentityKeyPair] = None
    ) -> BaseStateTypeT:
        self = cls()
        self.__identity_key_format = identity_key_format
        self.__hash_function = hash_function
        self.__info = info
        self.__identity_key = identity_key_pair or IdentityKeyPairSeed(secrets.token_bytes(32))
        self.__signed_pre_key = self.__generate_spk()
        self.__old_signed_pre_key = None
        self.__pre_keys = set()
        self.__hidden_pre_keys = set()
        return self

    @staticmethod
    @abstractmethod
    def _encode_public_key(key_format: IdentityKeyFormat, pub: bytes) -> bytes:
        raise NotImplementedError("Create a subclass of BaseState and implement `_encode_public_key`.")

    @property
    def model(self) -> BaseStateModel:
        return BaseStateModel(
            identity_key=self.__identity_key.model,
            signed_pre_key=self.__signed_pre_key.model,
            old_signed_pre_key=None if self.__old_signed_pre_key is None else self.__old_signed_pre_key.model,
            pre_keys=frozenset(pre_key.priv for pre_key in self.__pre_keys)
        )

    @property
    def json(self) -> JSONObject:
        return cast(JSONObject, json.loads(self.model.model_dump_json()))

    @classmethod
    def from_model(
        cls: Type[BaseStateTypeT],
        model: BaseStateModel,
        identity_key_format: IdentityKeyFormat,
        hash_function: HashFunction,
        info: bytes
    ) -> BaseStateTypeT:
        self = cls()
        self.__identity_key_format = identity_key_format
        self.__hash_function = hash_function
        self.__info = info
        self.__identity_key = IdentityKeyPair.from_model(model.identity_key)
        self.__signed_pre_key = SignedPreKeyPair.from_model(model.signed_pre_key)
        self.__old_signed_pre_key = (
            None
            if model.old_signed_pre_key is None
            else SignedPreKeyPair.from_model(model.old_signed_pre_key)
        )
        self.__pre_keys = { PreKeyPair(pre_key) for pre_key in model.pre_keys }
        self.__hidden_pre_keys = set()
        return self

    @classmethod
    def from_json(
        cls: Type[BaseStateTypeT],
        serialized: JSONObject,
        identity_key_format: IdentityKeyFormat,
        hash_function: HashFunction,
        info: bytes
    ) -> Tuple[BaseStateTypeT, bool]:
        model, bundle_needs_publish = parse_base_state_model(serialized)
        self = cls.from_model(
            model,
            identity_key_format,
            hash_function,
            info
        )
        return self, bundle_needs_publish

    def __generate_spk(self) -> SignedPreKeyPair:
        identity_key = self.__identity_key.as_priv().priv
        if self.__identity_key_format is IdentityKeyFormat.CURVE_25519:
            identity_key = xeddsa.priv_force_sign(identity_key, False)
        priv = secrets.token_bytes(32)
        sig = xeddsa.ed25519_priv_sign(
            identity_key,
            self._encode_public_key(IdentityKeyFormat.CURVE_25519, xeddsa.priv_to_curve25519_pub(priv))
        )
        return SignedPreKeyPair(priv=priv, sig=sig, timestamp=int(time.time()))

    @property
    def old_signed_pre_key(self) -> Optional[bytes]:
        return None if self.__old_signed_pre_key is None else self.__old_signed_pre_key.pub

    def signed_pre_key_age(self) -> int:
        return int(time.time()) - self.__signed_pre_key.timestamp

    def rotate_signed_pre_key(self) -> None:
        self.__old_signed_pre_key = self.__signed_pre_key
        self.__signed_pre_key = self.__generate_spk()

    @property
    def hidden_pre_keys(self) -> FrozenSet[bytes]:
        return frozenset(pre_key.pub for pre_key in self.__hidden_pre_keys)

    def hide_pre_key(self, pre_key_pub: bytes) -> bool:
        hidden_pre_keys = frozenset(filter(lambda pre_key: pre_key.pub == pre_key_pub, self.__pre_keys))
        self.__pre_keys -= hidden_pre_keys
        self.__hidden_pre_keys |= hidden_pre_keys
        return len(hidden_pre_keys) > 0

    def delete_pre_key(self, pre_key_pub: bytes) -> bool:
        deleted_pre_keys = frozenset(filter(
            lambda pre_key: pre_key.pub == pre_key_pub,
            self.__pre_keys | self.__hidden_pre_keys
        ))
        self.__pre_keys -= deleted_pre_keys
        self.__hidden_pre_keys -= deleted_pre_keys
        return len(deleted_pre_keys) > 0

    def delete_hidden_pre_keys(self) -> None:
        self.__hidden_pre_keys = set()

    def get_num_visible_pre_keys(self) -> int:
        return len(self.__pre_keys)

    def generate_pre_keys(self, num_pre_keys: int) -> None:
        for _ in range(num_pre_keys):
            self.__pre_keys.add(PreKeyPair(priv=secrets.token_bytes(32)))

    @property
    def bundle(self) -> Bundle:
        identity_key = self.__identity_key.as_priv().priv
        return Bundle(
            identity_key=(
                xeddsa.priv_to_curve25519_pub(identity_key)
                if self.__identity_key_format is IdentityKeyFormat.CURVE_25519
                else xeddsa.priv_to_ed25519_pub(identity_key)
            ),
            signed_pre_key=self.__signed_pre_key.pub,
            signed_pre_key_sig=self.__signed_pre_key.sig,
            pre_keys=frozenset(pre_key.pub for pre_key in self.__pre_keys)
        )

    async def get_shared_secret_active(
        self,
        bundle: Bundle,
        associated_data_appendix: bytes = b"",
        require_pre_key: bool = True
    ) -> Tuple[bytes, bytes, Header]:
        if len(bundle.pre_keys) == 0 and require_pre_key:
            raise KeyAgreementException("This bundle does not contain a pre key.")
        other_identity_key = bundle.identity_key
        if self.__identity_key_format is IdentityKeyFormat.CURVE_25519:
            other_identity_key = xeddsa.curve25519_pub_to_ed25519_pub(other_identity_key, False)
        if not xeddsa.ed25519_verify(
            bundle.signed_pre_key_sig,
            other_identity_key,
            self._encode_public_key(IdentityKeyFormat.CURVE_25519, bundle.signed_pre_key)
        ):
            raise KeyAgreementException("The signature of the signed pre key could not be verified.")
        pre_key = None if len(bundle.pre_keys) == 0 else secrets.choice(list(bundle.pre_keys))
        ephemeral_key = secrets.token_bytes(32)
        own_identity_key = self.__identity_key.as_priv().priv
        other_identity_key = bundle.identity_key
        if self.__identity_key_format is IdentityKeyFormat.ED_25519:
            other_identity_key = xeddsa.ed25519_pub_to_curve25519_pub(other_identity_key)
        dh1 = xeddsa.x25519(own_identity_key, bundle.signed_pre_key)
        dh2 = xeddsa.x25519(ephemeral_key, other_identity_key)
        dh3 = xeddsa.x25519(ephemeral_key, bundle.signed_pre_key)
        dh4 = b"" if pre_key is None else xeddsa.x25519(ephemeral_key, pre_key)
        salt = b"\x00" * self.__hash_function.hash_size
        padding = b"\xFF" * 32
        shared_secret = await CryptoProviderImpl.hkdf_derive(
            self.__hash_function,
            32,
            salt,
            self.__info,
            padding + dh1 + dh2 + dh3 + dh4
        )
        associated_data = (
            self._encode_public_key(self.__identity_key_format, self.bundle.identity_key)
            + self._encode_public_key(self.__identity_key_format, bundle.identity_key)
            + associated_data_appendix
        )
        header = Header(
            identity_key=self.bundle.identity_key,
            ephemeral_key=xeddsa.priv_to_curve25519_pub(ephemeral_key),
            pre_key=pre_key,
            signed_pre_key=bundle.signed_pre_key
        )
        return shared_secret, associated_data, header

    async def get_shared_secret_passive(
        self,
        header: Header,
        associated_data_appendix: bytes = b"",
        require_pre_key: bool = True
    ) -> Tuple[bytes, bytes, SignedPreKeyPair]:
        signed_pre_key: Optional[SignedPreKeyPair] = None
        if header.signed_pre_key == self.__signed_pre_key.pub:
            signed_pre_key = self.__signed_pre_key
        if self.__old_signed_pre_key is not None and header.signed_pre_key == self.__old_signed_pre_key.pub:
            signed_pre_key = self.__old_signed_pre_key
        if signed_pre_key is None:
            raise KeyAgreementException(
                "This key agreement attempt uses a signed pre key that is not available any more."
            )
        if header.pre_key is None and require_pre_key:
            raise KeyAgreementException("This key agreement attempt does not use a pre key.")
        pre_key: Optional[bytes] = None
        if header.pre_key is not None:
            pre_key = next((
                pre_key.priv
                for pre_key
                in self.__pre_keys | self.__hidden_pre_keys
                if pre_key.pub == header.pre_key
            ), None)
            if pre_key is None:
                raise KeyAgreementException(
                    "This key agreement attempt uses a pre key that is not available any more."
                )
        own_identity_key = self.__identity_key.as_priv().priv
        other_identity_key = header.identity_key
        if self.__identity_key_format is IdentityKeyFormat.ED_25519:
            other_identity_key = xeddsa.ed25519_pub_to_curve25519_pub(other_identity_key)
        dh1 = xeddsa.x25519(signed_pre_key.priv, other_identity_key)
        dh2 = xeddsa.x25519(own_identity_key, header.ephemeral_key)
        dh3 = xeddsa.x25519(signed_pre_key.priv, header.ephemeral_key)
        dh4 = b"" if pre_key is None else xeddsa.x25519(pre_key, header.ephemeral_key)
        salt = b"\x00" * self.__hash_function.hash_size
        padding = b"\xFF" * 32
        shared_secret = await CryptoProviderImpl.hkdf_derive(
            self.__hash_function,
            32,
            salt,
            self.__info,
            padding + dh1 + dh2 + dh3 + dh4
        )
        associated_data = (
            self._encode_public_key(self.__identity_key_format, header.identity_key)
            + self._encode_public_key(self.__identity_key_format, self.bundle.identity_key)
            + associated_data_appendix
        )
        return shared_secret, associated_data, signed_pre_key

# ---- x3dh/state.py ----

StateTypeT = TypeVar("StateTypeT", bound="State")

class State(BaseState):
    def __init__(self) -> None:
        super().__init__()
        self.__signed_pre_key_rotation_period: int
        self.__pre_key_refill_threshold: int
        self.__pre_key_refill_target: int

    @classmethod
    def create(
        cls: Type[StateTypeT],
        identity_key_format: IdentityKeyFormat,
        hash_function: HashFunction,
        info: bytes,
        identity_key_pair: Optional[IdentityKeyPair] = None,
        signed_pre_key_rotation_period: int = 7 * 24 * 60 * 60,
        pre_key_refill_threshold: int = 99,
        pre_key_refill_target: int = 100
    ) -> StateTypeT:
        if signed_pre_key_rotation_period < 1:
            raise ValueError(
                "Invalid value passed for the `signed_pre_key_rotation_period` parameter. The signed pre key"
                " rotation period must be at least one day."
            )
        if not 1 <= pre_key_refill_threshold <= pre_key_refill_target:
            raise ValueError(
                "Invalid value(s) passed for the `pre_key_refill_threshold` / `pre_key_refill_target`"
                " parameter(s). `pre_key_refill_threshold` must be greater than or equal to '1' and lower"
                " than or equal to `pre_key_refill_target`."
            )
        self = super().create(identity_key_format, hash_function, info, identity_key_pair)
        self.__signed_pre_key_rotation_period = signed_pre_key_rotation_period
        self.__pre_key_refill_threshold = pre_key_refill_threshold
        self.__pre_key_refill_target = pre_key_refill_target
        self.generate_pre_keys(pre_key_refill_target)
        self._publish_bundle(self.bundle)
        return self

    @abstractmethod
    def _publish_bundle(self, bundle: Bundle) -> None:
        raise NotImplementedError("Create a subclass of State and implement `_publish_bundle`.")

    @classmethod
    def from_model(
        cls: Type[StateTypeT],
        model: BaseStateModel,
        identity_key_format: IdentityKeyFormat,
        hash_function: HashFunction,
        info: bytes,
        signed_pre_key_rotation_period: int = 7 * 24 * 60 * 60,
        pre_key_refill_threshold: int = 99,
        pre_key_refill_target: int = 100
    ) -> StateTypeT:
        if signed_pre_key_rotation_period < 1:
            raise ValueError(
                "Invalid value passed for the `signed_pre_key_rotation_period` parameter. The signed pre key"
                " rotation period must be at least one day."
            )
        if not 1 <= pre_key_refill_threshold <= pre_key_refill_target:
            raise ValueError(
                "Invalid value(s) passed for the `pre_key_refill_threshold` / `pre_key_refill_target`"
                " parameter(s). `pre_key_refill_threshold` must be greater than or equal to '1' and lower"
                " than or equal to `pre_key_refill_target`."
            )
        self = super().from_model(model, identity_key_format, hash_function, info)
        self.__signed_pre_key_rotation_period = signed_pre_key_rotation_period
        self.__pre_key_refill_threshold = pre_key_refill_threshold
        self.__pre_key_refill_target = pre_key_refill_target
        self.rotate_signed_pre_key()
        return self

    @classmethod
    def from_json(
        cls: Type[StateTypeT],
        serialized: JSONObject,
        identity_key_format: IdentityKeyFormat,
        hash_function: HashFunction,
        info: bytes,
        signed_pre_key_rotation_period: int = 7 * 24 * 60 * 60,
        pre_key_refill_threshold: int = 99,
        pre_key_refill_target: int = 100
    ) -> Tuple[StateTypeT, bool]:
        model, bundle_needs_publish = parse_base_state_model(serialized)
        self = cls.from_model(
            model,
            identity_key_format,
            hash_function,
            info,
            signed_pre_key_rotation_period,
            pre_key_refill_threshold,
            pre_key_refill_target
        )
        if bundle_needs_publish:
            self._publish_bundle(self.bundle)
        return self, False

    def rotate_signed_pre_key(self, force: bool = False) -> None:
        if force or self.signed_pre_key_age() > self.__signed_pre_key_rotation_period:
            super().rotate_signed_pre_key()
            self._publish_bundle(self.bundle)

    async def get_shared_secret_passive(
        self,
        header: Header,
        associated_data_appendix: bytes = b"",
        require_pre_key: bool = True
    ) -> Tuple[bytes, bytes, SignedPreKeyPair]:
        shared_secret, associated_data, signed_pre_key_pair = await super().get_shared_secret_passive(
            header,
            associated_data_appendix,
            require_pre_key
        )
        if header.pre_key is not None:
            self.delete_pre_key(header.pre_key)
            if self.get_num_visible_pre_keys() < self.__pre_key_refill_threshold:
                self.generate_pre_keys(self.__pre_key_refill_target - self.get_num_visible_pre_keys())
            self._publish_bundle(self.bundle)
        return shared_secret, associated_data, signed_pre_key_pair


class X3DHState(State):
    @staticmethod
    def _encode_public_key(key_format: IdentityKeyFormat, pub: bytes) -> bytes:
        if key_format is IdentityKeyFormat.CURVE_25519:
            return pub
        elif key_format is IdentityKeyFormat.ED_25519:
            return xeddsa.curve25519_pub_to_ed25519_pub(pub, False)
        raise ValueError(f"Unknown IdentityKeyFormat: {key_format}")
