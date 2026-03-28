"""
POS passcode authentication routes.
No credentials required to fetch staff list (restaurant_id is the device's "key").
Passcode login returns a full JWT like the regular login.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
from uuid import UUID

from ..database import get_db
from ..models import User
from ..schemas import POSStaffMember, POSPasscodeLoginRequest, POSLoginResponse
from ..security import verify_password, create_access_token, create_refresh_token, hash_password
from shared.models.enums import UserRole

router = APIRouter(tags=["POS Auth"])

# Roles allowed to log in via POS passcode
_POS_ROLES = {UserRole.STAFF, UserRole.CHEF, UserRole.RESTAURANT_ADMIN}


@router.get("/pos/staff", response_model=List[POSStaffMember])
async def list_pos_staff(restaurant_id: UUID, db: AsyncSession = Depends(get_db)):
    """
    Return active staff/chef names for the POS login screen.
    Only shows users that have a pos_passcode set.
    No authentication required — restaurant_id is the device's identifier.
    """
    result = await db.execute(
        select(User).where(
            User.restaurant_id == restaurant_id,
            User.is_active == True,
            User.pos_passcode != None,
            User.role.in_([r.name for r in _POS_ROLES]),
        ).order_by(User.full_name)
    )
    users = result.scalars().all()
    return [POSStaffMember(id=u.id, full_name=u.full_name or u.username, role=u.role.value if hasattr(u.role, 'value') else str(u.role)) for u in users]


@router.post("/pos/login", response_model=POSLoginResponse)
async def pos_passcode_login(data: POSPasscodeLoginRequest, db: AsyncSession = Depends(get_db)):
    """
    Login with a 4-digit POS passcode.
    Finds the staff member in this restaurant whose passcode matches.
    Returns a JWT identical to a regular login.
    """
    result = await db.execute(
        select(User).where(
            User.restaurant_id == data.restaurant_id,
            User.is_active == True,
            User.pos_passcode != None,
            User.role.in_([r.name for r in _POS_ROLES]),
        )
    )
    users = result.scalars().all()

    matched = next((u for u in users if verify_password(data.passcode, u.pos_passcode)), None)
    if not matched:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid passcode")

    from ..schemas import UserResponse
    access_token = create_access_token({"sub": str(matched.id), "role": matched.role.name if hasattr(matched.role, 'name') else str(matched.role)})
    refresh_token = create_refresh_token({"sub": str(matched.id)})

    return POSLoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=3600,
        user=UserResponse.model_validate(matched),
    )
