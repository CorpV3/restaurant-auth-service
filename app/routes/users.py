"""User management routes for master admin"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, or_
from typing import List, Optional
from uuid import UUID

from ..database import get_db
from ..models import User
from ..schemas import UserResponse, UserCreate, UserUpdate, StaffCreate
from ..dependencies import get_current_user, require_master_admin
from ..security import hash_password
from shared.models.enums import UserRole

router = APIRouter(tags=["users"])


@router.get("/users")
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_master_admin)
):
    """List all users (master admin only)"""
    try:
        result = await db.execute(
            select(User).order_by(User.created_at.desc())
        )
        users = result.scalars().all()
        # Debug: Print user data
        print(f"DEBUG list_users: Retrieved {len(users)} users")
        for user in users:
            print(f"DEBUG: User {user.username}, role={user.role}, role_type={type(user.role)}")

        # Try to manually serialize
        response_list = []
        for user in users:
            try:
                user_response = UserResponse.model_validate(user)
                response_list.append(user_response)
                print(f"DEBUG: Serialized {user.username} successfully")
            except Exception as e:
                print(f"ERROR serializing user {user.username}: {type(e).__name__}: {str(e)}")
                import traceback
                traceback.print_exc()
                raise

        print(f"DEBUG list_users: Returning {len(response_list)} users")
        return response_list
    except Exception as e:
        print(f"ERROR in list_users: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        raise


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_master_admin)
):
    """Get a specific user by ID (master admin only)"""
    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return user


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    user_update: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_master_admin)
):
    """Update a user (master admin only)"""
    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Update user fields
    update_data = user_update.model_dump(exclude_unset=True)

    # Hash password if provided
    if 'password' in update_data and update_data['password']:
        update_data['hashed_password'] = hash_password(update_data.pop('password'))

    for field, value in update_data.items():
        setattr(user, field, value)

    await db.commit()
    await db.refresh(user)

    return user


@router.delete("/{user_id}")
async def delete_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_master_admin)
):
    """Delete a user (master admin only)"""
    # Prevent deleting yourself
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )

    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    await db.delete(user)
    await db.commit()

    return {"message": "User deleted successfully"}


# Staff Management Endpoints (Restaurant Admin)

@router.get("/staff/{restaurant_id}", response_model=List[UserResponse])
async def list_staff(
    restaurant_id: UUID,
    role: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List staff for a restaurant (chefs and customers)
    Restaurant admin can only see their own restaurant's staff
    """
    # Restaurant admins can only view their own restaurant's staff
    if current_user.role == UserRole.RESTAURANT_ADMIN and current_user.restaurant_id != restaurant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this restaurant's staff"
        )

    # Build query for staff (CHEF and CUSTOMER roles only)
    query = select(User).where(User.restaurant_id == restaurant_id)

    # Filter by role if provided
    if role:
        role_upper = role.upper()
        if role_upper == "CHEF":
            query = query.where(User.role == UserRole.CHEF)
        elif role_upper == "CUSTOMER":
            query = query.where(User.role == UserRole.CUSTOMER)
    else:
        # If no role filter, show CHEF, STAFF and CUSTOMER
        query = query.where(or_(
            User.role == UserRole.CHEF,
            User.role == UserRole.STAFF,
            User.role == UserRole.CUSTOMER
        ))

    query = query.order_by(User.created_at.desc())

    result = await db.execute(query)
    staff = result.scalars().all()

    return staff


@router.post("/chef", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_chef(
    user_data: StaffCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Create a new chef account
    Restaurant admin can create chefs for their restaurant
    """
    # Restaurant admins can only create chefs for their own restaurant
    if current_user.role == UserRole.RESTAURANT_ADMIN:
        if user_data.restaurant_id != current_user.restaurant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to create chefs for other restaurants"
            )

    # Check if username already exists
    existing_user = await db.execute(
        select(User).where(User.username == user_data.username)
    )
    if existing_user.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    # Create chef user
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=hash_password(user_data.password),
        role=UserRole.CHEF,
        restaurant_id=user_data.restaurant_id,
        is_active=True,
        pos_passcode=hash_password(user_data.pos_passcode) if user_data.pos_passcode else None,
    )

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return new_user


@router.post("/customer", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_customer(
    user_data: StaffCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Create a new customer account
    Restaurant admin can create customers for their restaurant
    """
    # Restaurant admins can only create customers for their own restaurant
    if current_user.role == UserRole.RESTAURANT_ADMIN:
        if user_data.restaurant_id != current_user.restaurant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to create customers for other restaurants"
            )

    # Check if username already exists
    existing_user = await db.execute(
        select(User).where(User.username == user_data.username)
    )
    if existing_user.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    # Create customer user
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=hash_password(user_data.password),
        role=UserRole.CUSTOMER,
        restaurant_id=user_data.restaurant_id,
        is_active=True
    )

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return new_user


@router.post("/staff", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_staff(
    user_data: StaffCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Create a new staff account (POS cashier / floor staff)
    Restaurant admin can create staff for their restaurant
    """
    if current_user.role == UserRole.RESTAURANT_ADMIN:
        if user_data.restaurant_id != current_user.restaurant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to create staff for other restaurants"
            )

    existing_user = await db.execute(
        select(User).where(User.username == user_data.username)
    )
    if existing_user.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    new_user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=hash_password(user_data.password),
        role=UserRole.STAFF,
        restaurant_id=user_data.restaurant_id,
        is_active=True,
        pos_passcode=hash_password(user_data.pos_passcode) if user_data.pos_passcode else None,
    )

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return new_user


@router.delete("/staff/{staff_id}")
async def delete_staff(
    staff_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a staff account"""
    result = await db.execute(
        select(User).where(User.id == staff_id, User.role == UserRole.STAFF)
    )
    staff = result.scalar_one_or_none()

    if not staff:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Staff member not found"
        )

    if current_user.role == UserRole.RESTAURANT_ADMIN and staff.restaurant_id != current_user.restaurant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this staff member"
        )

    await db.delete(staff)
    await db.commit()

    return {"message": "Staff member deleted successfully"}


@router.delete("/chef/{chef_id}")
async def delete_chef(
    chef_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a chef account"""
    result = await db.execute(
        select(User).where(User.id == chef_id, User.role == UserRole.CHEF)
    )
    chef = result.scalar_one_or_none()

    if not chef:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chef not found"
        )

    # Restaurant admins can only delete their own restaurant's chefs
    if current_user.role == UserRole.RESTAURANT_ADMIN and chef.restaurant_id != current_user.restaurant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this chef"
        )

    await db.delete(chef)
    await db.commit()

    return {"message": "Chef deleted successfully"}


@router.delete("/customer/{customer_id}")
async def delete_customer(
    customer_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a customer account"""
    result = await db.execute(
        select(User).where(User.id == customer_id, User.role == UserRole.CUSTOMER)
    )
    customer = result.scalar_one_or_none()

    if not customer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Customer not found"
        )

    # Restaurant admins can only delete their own restaurant's customers
    if current_user.role == UserRole.RESTAURANT_ADMIN and customer.restaurant_id != current_user.restaurant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this customer"
        )

    await db.delete(customer)
    await db.commit()

    return {"message": "Customer deleted successfully"}


@router.patch("/{user_id}", response_model=UserResponse)
async def update_staff(
    user_id: UUID,
    user_update: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update staff member details"""
    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Restaurant admins can only update their own restaurant's staff
    if current_user.role == UserRole.RESTAURANT_ADMIN and user.restaurant_id != current_user.restaurant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this user"
        )

    # Update user fields
    update_data = user_update.model_dump(exclude_unset=True)

    # Hash password if provided
    if 'password' in update_data and update_data['password']:
        update_data['hashed_password'] = hash_password(update_data.pop('password'))

    # Hash pos_passcode if provided
    if 'pos_passcode' in update_data:
        pc = update_data.pop('pos_passcode')
        update_data['pos_passcode'] = hash_password(pc) if pc else None

    for field, value in update_data.items():
        if hasattr(user, field):
            setattr(user, field, value)

    await db.commit()
    await db.refresh(user)

    return user


@router.patch("/{user_id}/toggle-status", response_model=UserResponse)
async def toggle_staff_status(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Toggle staff member active/inactive status"""
    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Restaurant admins can only toggle their own restaurant's staff
    if current_user.role == UserRole.RESTAURANT_ADMIN and user.restaurant_id != current_user.restaurant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this user"
        )

    # Prevent deactivating yourself
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account"
        )

    user.is_active = not user.is_active
    await db.commit()
    await db.refresh(user)

    return user
