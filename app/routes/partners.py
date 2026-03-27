"""
Partner routes — signup, login, profile, admin approval
"""
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID

from ..database import get_db
from ..models import Partner
from ..schemas import (
    PartnerSignup, PartnerLogin, PartnerUpdate,
    PartnerResponse, PartnerTokenResponse, MessageResponse
)
from ..security import hash_password, verify_password, create_access_token, decode_token, security
from fastapi.security import HTTPAuthorizationCredentials
from shared.utils.logger import setup_logger

router = APIRouter()
logger = setup_logger("partner-routes")


def _partner_token(partner: Partner) -> PartnerTokenResponse:
    from shared.config.settings import settings
    token = create_access_token({
        "sub": str(partner.id),
        "role": "partner",
        "partner_id": str(partner.id),
    })
    return PartnerTokenResponse(
        access_token=token,
        expires_in=settings.access_token_expire_minutes * 60,
        partner=partner,
    )


async def get_current_partner(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> Partner:
    payload = decode_token(credentials.credentials)
    if payload.get("role") != "partner":
        raise HTTPException(status_code=403, detail="Not a partner token")
    partner = await db.get(Partner, UUID(payload["partner_id"]))
    if not partner or not partner.is_active:
        raise HTTPException(status_code=401, detail="Partner not found or inactive")
    return partner


async def get_master_admin(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
):
    """Simple admin check — validates JWT role=master_admin"""
    payload = decode_token(credentials.credentials)
    if payload.get("role") != "master_admin":
        raise HTTPException(status_code=403, detail="Master admin only")
    return payload


# ─── Public endpoints ─────────────────────────────────────────────────────────

@router.post("/signup", response_model=PartnerResponse, status_code=201)
async def partner_signup(payload: PartnerSignup, db: AsyncSession = Depends(get_db)):
    # Check username
    r = await db.execute(select(Partner).where(Partner.username == payload.username))
    if r.scalar_one_or_none():
        raise HTTPException(400, "Username already taken")
    # Check email
    r = await db.execute(select(Partner).where(Partner.email == payload.email))
    if r.scalar_one_or_none():
        raise HTTPException(400, "Email already registered")

    partner = Partner(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        company_name=payload.company_name,
        phone=payload.phone,
        commission_type=payload.commission_type,
        commission_value=payload.commission_value,
        is_approved=False,
    )
    db.add(partner)
    await db.commit()
    await db.refresh(partner)
    logger.info(f"Partner signed up: {partner.username}")
    return partner


@router.post("/login", response_model=PartnerTokenResponse)
async def partner_login(payload: PartnerLogin, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(Partner).where(Partner.username == payload.username))
    partner = r.scalar_one_or_none()
    if not partner or not verify_password(payload.password, partner.hashed_password):
        raise HTTPException(401, "Invalid credentials")
    if not partner.is_active:
        raise HTTPException(403, "Account deactivated")
    if not partner.is_approved:
        raise HTTPException(403, "Account pending approval")
    partner.last_login = datetime.utcnow()
    await db.commit()
    await db.refresh(partner)
    return _partner_token(partner)


# ─── Partner self-service ─────────────────────────────────────────────────────

@router.get("/me", response_model=PartnerResponse)
async def get_partner_me(partner: Partner = Depends(get_current_partner)):
    return partner


@router.patch("/me", response_model=PartnerResponse)
async def update_partner_me(
    payload: PartnerUpdate,
    partner: Partner = Depends(get_current_partner),
    db: AsyncSession = Depends(get_db),
):
    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(partner, k, v)
    partner.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(partner)
    return partner


# ─── Master Admin endpoints ───────────────────────────────────────────────────

@router.get("/admin/list", response_model=list[PartnerResponse])
async def list_partners(
    approved: bool = None,
    _=Depends(get_master_admin),
    db: AsyncSession = Depends(get_db),
):
    q = select(Partner)
    if approved is not None:
        q = q.where(Partner.is_approved == approved)
    q = q.order_by(Partner.created_at.desc())
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/admin/{partner_id}", response_model=PartnerResponse)
async def get_partner(
    partner_id: UUID,
    _=Depends(get_master_admin),
    db: AsyncSession = Depends(get_db),
):
    partner = await db.get(Partner, partner_id)
    if not partner:
        raise HTTPException(404, "Partner not found")
    return partner


@router.patch("/admin/{partner_id}/approve", response_model=PartnerResponse)
async def approve_partner(
    partner_id: UUID,
    _=Depends(get_master_admin),
    db: AsyncSession = Depends(get_db),
):
    partner = await db.get(Partner, partner_id)
    if not partner:
        raise HTTPException(404, "Partner not found")
    partner.is_approved = True
    partner.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(partner)
    logger.info(f"Partner approved: {partner.username}")
    return partner


@router.patch("/admin/{partner_id}/reject", response_model=PartnerResponse)
async def reject_partner(
    partner_id: UUID,
    _=Depends(get_master_admin),
    db: AsyncSession = Depends(get_db),
):
    partner = await db.get(Partner, partner_id)
    if not partner:
        raise HTTPException(404, "Partner not found")
    partner.is_approved = False
    partner.is_active = False
    partner.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(partner)
    return partner


@router.patch("/admin/{partner_id}/commission", response_model=PartnerResponse)
async def update_partner_commission(
    partner_id: UUID,
    payload: PartnerUpdate,
    _=Depends(get_master_admin),
    db: AsyncSession = Depends(get_db),
):
    partner = await db.get(Partner, partner_id)
    if not partner:
        raise HTTPException(404, "Partner not found")
    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(partner, k, v)
    partner.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(partner)
    return partner
