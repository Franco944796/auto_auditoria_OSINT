from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.db import utcnow
from app.identity.tokens import hash_token, new_otp, new_url_token, tokens_match
from app.identity.types import VerifiedIdentity
from app.models import Session, User, VerificationToken

OTP = "otp"
LINK = "link"
SESSION = "session"


@dataclass(frozen=True, slots=True)
class IssuedVerification:
    otp: str
    link_token: str


def normalize_email(email: str) -> str:
    return email.strip().lower()


class VerificationService:
    def __init__(self, db: AsyncSession, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self._secret = settings.secret_key.get_secret_value()

    def _hash(self, purpose: str, value: str) -> str:
        return hash_token(self._secret, purpose, value)

    async def start(self, email: str) -> IssuedVerification:
        email = normalize_email(email)
        now = utcnow()
        await self._purge_expired()

        user = await self.db.scalar(select(User).where(User.email == email))
        if user is None:
            user = User(email=email)
            self.db.add(user)
            await self.db.flush()

        # Pedir un código nuevo anula los anteriores: solo vale el último mail recibido.
        await self.db.execute(
            update(VerificationToken)
            .where(VerificationToken.user_id == user.id, VerificationToken.consumed_at.is_(None))
            .values(consumed_at=now)
        )
        issued = IssuedVerification(otp=new_otp(), link_token=new_url_token())
        self.db.add(
            VerificationToken(
                user_id=user.id,
                otp_hash=self._hash(OTP, issued.otp),
                link_hash=self._hash(LINK, issued.link_token),
                expires_at=now + timedelta(minutes=self.settings.verification_ttl_minutes),
            )
        )
        await self.db.commit()
        return issued

    async def verify_code(self, email: str, code: str) -> VerifiedIdentity | None:
        user = await self.db.scalar(select(User).where(User.email == normalize_email(email)))
        if user is None:
            return None
        token = await self.db.scalar(
            select(VerificationToken)
            .where(
                VerificationToken.user_id == user.id,
                VerificationToken.consumed_at.is_(None),
                VerificationToken.expires_at > utcnow(),
            )
            .order_by(VerificationToken.created_at.desc())
        )
        if token is None:
            return None
        if not tokens_match(token.otp_hash, self._hash(OTP, code)):
            token.attempts += 1
            if token.attempts >= self.settings.verification_max_attempts:
                token.consumed_at = utcnow()
            await self.db.commit()
            return None
        return await self._consume(token, user)

    async def verify_link(self, link_token: str) -> VerifiedIdentity | None:
        token = await self.db.scalar(
            select(VerificationToken).where(
                VerificationToken.link_hash == self._hash(LINK, link_token),
                VerificationToken.consumed_at.is_(None),
                VerificationToken.expires_at > utcnow(),
            )
        )
        if token is None:
            return None
        user = await self.db.get(User, token.user_id)
        if user is None:
            return None
        return await self._consume(token, user)

    async def _consume(self, token: VerificationToken, user: User) -> VerifiedIdentity:
        now = utcnow()
        token.consumed_at = now
        if user.verified_at is None:
            user.verified_at = now
        await self.db.commit()
        return VerifiedIdentity(user_id=user.id, email=user.email)

    async def create_session(self, identity: VerifiedIdentity) -> str:
        raw = new_url_token()
        self.db.add(
            Session(
                user_id=identity.user_id,
                token_hash=self._hash(SESSION, raw),
                expires_at=utcnow() + timedelta(minutes=self.settings.session_ttl_minutes),
            )
        )
        await self.db.commit()
        return raw

    async def resolve_session(self, raw: str) -> VerifiedIdentity | None:
        row = await self.db.execute(
            select(User)
            .join(Session, Session.user_id == User.id)
            .where(
                Session.token_hash == self._hash(SESSION, raw),
                Session.expires_at > utcnow(),
                User.verified_at.is_not(None),
            )
        )
        user = row.scalar_one_or_none()
        if user is None:
            return None
        return VerifiedIdentity(user_id=user.id, email=user.email)

    async def end_session(self, raw: str) -> None:
        await self.db.execute(delete(Session).where(Session.token_hash == self._hash(SESSION, raw)))
        await self.db.commit()

    async def delete_account(self, identity: VerifiedIdentity) -> None:
        # Borrado explícito de hijos: SQLite no aplica ON DELETE CASCADE sin PRAGMA foreign_keys.
        await self.db.execute(delete(Session).where(Session.user_id == identity.user_id))
        await self.db.execute(
            delete(VerificationToken).where(VerificationToken.user_id == identity.user_id)
        )
        await self.db.execute(delete(User).where(User.id == identity.user_id))
        await self.db.commit()

    async def _purge_expired(self) -> None:
        now = utcnow()
        await self.db.execute(delete(Session).where(Session.expires_at <= now))
        await self.db.execute(delete(VerificationToken).where(VerificationToken.expires_at <= now))
