import re
from datetime import timedelta
from typing import List

from fastapi import APIRouter, Depends, HTTPException

from app.core.config import get_settings
from app.core.deps import MANAGEMENT, get_current_user
from app.core.security import (
    create_device_refresh_token,
    create_device_token,
    generate_device_code,
    is_expired,
    normalize_device_code,
)
from app.db.mongo import db
from app.db.serialization import to_mongo
from app.models.common import Role, utcnow
from app.models.user import (
    DeviceActivate,
    DeviceActivation,
    DeviceAssign,
    DeviceCodeRequest,
    DeviceLogout,
    DevicePoll,
    StaffInvite,
    User,
    WaiterUpdate,
)
from app.services.auth_otp import send_first_login_otp

router = APIRouter(tags=["staff"])
settings = get_settings()

# Everyone an owner/manager can see and administer on the roster.
_ROSTER_ROLES = [Role.waiter.value, Role.kitchen.value, Role.manager.value]


def _grouped(code: str) -> str:
    """Format a normalized code as XXXX-XXXX-XXXX for display."""
    return "-".join(code[i:i + 4] for i in range(0, len(code), 4))


def _device_tokens(device_id: str, cafe_id: str) -> dict:
    return {
        "token": create_device_token(device_id, cafe_id),
        "refresh_token": create_device_refresh_token(device_id, cafe_id),
    }


async def _assigned_user(activation: dict) -> dict | None:
    """The staff member currently assigned to a device, or None (ordering-only)."""
    uid = activation.get("user_id")
    if not uid:
        return None
    return await db.users.find_one({"id": uid}, {"_id": 0, "id": 1, "name": 1})


def _guard_manager_boundary(current_user: dict, target: dict) -> None:
    """A manager can't create, edit, deactivate, reactivate, or delete another
    manager — only the owner can. Owner is unrestricted."""
    if current_user["role"] == Role.manager.value and target["role"] == Role.manager.value:
        raise HTTPException(status_code=403, detail="Managers can't manage other managers.")


async def _find_staff_or_404(staff_id: str, cafe_id: str) -> dict:
    staff = await db.users.find_one(
        {"id": staff_id, "cafe_id": cafe_id, "role": {"$in": _ROSTER_ROLES}}, {"_id": 0}
    )
    if not staff:
        raise HTTPException(status_code=404, detail="Staff member not found.")
    return staff


# ---- Staff invite (replaces name-only roster creation) ----

@router.post("/staff")
async def create_staff(payload: StaffInvite, current_user: dict = Depends(MANAGEMENT)):
    """Invite a new staff member — one endpoint for every role. Creates the
    user row immediately (unverified, no password) and emails a first-login
    OTP right away; the invite itself is that user's first-login trigger."""
    if current_user["role"] == Role.manager.value and payload.role == Role.manager.value:
        raise HTTPException(status_code=403, detail="Managers can't add other managers.")

    if await db.users.find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered.")

    staff = User(
        email=payload.email, name=payload.name, role=payload.role,
        cafe_id=current_user["cafe_id"], is_email_verified=False,
        created_by=current_user.get("user_id"),
    )
    doc = to_mongo(staff)
    await db.users.insert_one(doc)
    otp = await send_first_login_otp(db, doc)

    resp = staff.model_dump(mode="json")
    if otp:  # DEV convenience: no mailbox required locally.
        resp["dev_otp"] = otp
    return resp


@router.post("/staff/{staff_id}/resend-invite")
async def resend_invite(staff_id: str, current_user: dict = Depends(MANAGEMENT)):
    """Re-send the first-login OTP if the original expired or got lost."""
    staff = await _find_staff_or_404(staff_id, current_user["cafe_id"])
    if staff.get("is_email_verified"):
        raise HTTPException(status_code=400, detail="This staff member has already signed in.")

    otp = await send_first_login_otp(db, staff)
    resp = {"message": "Invite re-sent."}
    if otp:
        resp["dev_otp"] = otp
    return resp


@router.get("/staff", response_model=List[User])
async def get_staff(current_user: dict = Depends(MANAGEMENT)):
    """List staff for the manager's cafe (active and deactivated)."""
    return await db.users.find(
        {"cafe_id": current_user["cafe_id"], "role": {"$in": _ROSTER_ROLES}}, {"_id": 0, "password": 0},
    ).to_list(1000)


@router.patch("/staff/{staff_id}", response_model=User)
async def update_staff(staff_id: str, payload: WaiterUpdate, current_user: dict = Depends(MANAGEMENT)):
    """Edit a staff roster entry's name."""
    staff = await _find_staff_or_404(staff_id, current_user["cafe_id"])
    _guard_manager_boundary(current_user, staff)

    updates: dict = {}
    if payload.name is not None and payload.name.strip():
        updates["name"] = payload.name.strip()
    if updates:
        await db.users.update_one({"id": staff_id}, {"$set": updates})

    return await db.users.find_one({"id": staff_id}, {"_id": 0, "password": 0})


@router.get("/staff/{staff_id}/stats")
async def staff_stats(staff_id: str, current_user: dict = Depends(MANAGEMENT)):
    """Per-staff analytics: orders taken, tables served, revenue, and recent bills."""
    cafe_id = current_user["cafe_id"]
    staff = await _find_staff_or_404(staff_id, cafe_id)

    orders = await db.orders.find({"cafe_id": cafe_id, "waiter_id": staff_id}, {"_id": 0}).to_list(10000)
    tables_served = {o["table_id"] for o in orders if o.get("table_id")}
    items_sold = sum(i.get("quantity", 0) for o in orders for i in o.get("items", []))

    bills = await db.bills.find(
        {"cafe_id": cafe_id, "waiter_id": staff_id, "soft_deleted": False}, {"_id": 0}
    ).sort("bill_number", -1).to_list(10000)
    revenue = sum(b.get("total", 0) for b in bills)

    payment_breakdown: dict[str, float] = {}
    item_counts: dict[str, int] = {}
    for b in bills:
        payment_breakdown[b["payment_method"]] = payment_breakdown.get(b["payment_method"], 0.0) + b["total"]
        for it in b.get("items", []):
            item_counts[it["menu_item_name"]] = item_counts.get(it["menu_item_name"], 0) + it["quantity"]

    recent = [
        {
            "id": b["id"],
            "bill_number": b["bill_number"],
            "total": b["total"],
            "payment_method": b["payment_method"],
            "table_id": b.get("table_id"),
            "created_at": b["created_at"],
            "item_count": sum(i["quantity"] for i in b.get("items", [])),
        }
        for b in bills[:15]
    ]

    return {
        "staff": staff,
        "orders_taken": len(orders),
        "tables_served": len(tables_served),
        "items_sold": items_sold,
        "bills_count": len(bills),
        "revenue": revenue,
        "avg_bill": (revenue / len(bills)) if bills else 0,
        "payment_breakdown": payment_breakdown,
        "top_items": sorted(item_counts.items(), key=lambda x: x[1], reverse=True)[:5],
        "recent_bills": recent,
        "last_active": staff.get("last_active"),
    }


# ---- Device pairing (device-code only; manager sets who's on the device) ----
# Deferred to Slice 6 — still live and tested under its original /waiters path.

@router.post("/waiters/devices/request")
async def request_device_code(payload: DeviceCodeRequest):
    """A device asks for a pairing code. The manager activates it from the panel."""
    pending = await db.device_activations.find_one(
        {"device_id": payload.device_id, "status": "pending"}
    )
    if pending and not is_expired(pending["expires_at"]):
        return {"code": _grouped(pending["code"]), "expires_at": pending["expires_at"]}
    if pending:
        await db.device_activations.delete_one({"_id": pending["_id"]})

    activation = DeviceActivation(
        device_id=payload.device_id,
        code=normalize_device_code(generate_device_code()),
        expires_at=utcnow() + timedelta(minutes=settings.device_code_expiry_minutes),
    )
    doc = to_mongo(activation)
    doc["expires_at"] = activation.expires_at  # real BSON date for TTL + comparison
    await db.device_activations.insert_one(doc)
    return {"code": _grouped(activation.code), "expires_at": activation.expires_at}


@router.post("/waiters/devices/poll")
async def poll_device(payload: DevicePoll):
    """Device polls with its code; once a manager activates it, a device token is
    issued. The current waiter (if any) is resolved live on each request."""
    code = normalize_device_code(payload.code)
    activation = await db.device_activations.find_one({"device_id": payload.device_id, "code": code})
    if not activation:
        raise HTTPException(status_code=404, detail="Unknown device code.")
    if activation["status"] != "active":
        return {"status": "pending"}

    await db.device_activations.update_one(
        {"_id": activation["_id"]}, {"$set": {"signed_in": True, "last_login": utcnow()}}
    )
    return {
        "status": "active",
        **_device_tokens(activation["device_id"], activation["cafe_id"]),
        "device": {
            "device_id": activation["device_id"],
            "device_name": activation.get("device_name"),
            "assigned_user": await _assigned_user(activation),
        },
    }


@router.get("/devices/me")
async def device_me(current_user: dict = Depends(get_current_user)):
    """The current device's name + assigned waiter (live). Used by the waiter app
    to show who is on the device and to attribute orders."""
    if not current_user.get("device_id"):
        raise HTTPException(status_code=400, detail="Not a device session.")
    activation = await db.device_activations.find_one(
        {"device_id": current_user["device_id"], "status": "active"}, {"_id": 0}
    )
    if not activation:
        raise HTTPException(status_code=401, detail="Device is no longer authorized.")
    return {
        "device_id": activation["device_id"],
        "device_name": activation.get("device_name"),
        "assigned_user": await _assigned_user(activation),
    }


@router.post("/waiters/devices/activate")
async def activate_device(payload: DeviceActivate, current_user: dict = Depends(MANAGEMENT)):
    """Manager authorizes a pending device by its code. Optionally names it and
    assigns the current waiter (both can be changed later)."""
    cafe_id = current_user["cafe_id"]
    waiter = None
    if payload.waiter_id:
        waiter = await db.users.find_one(
            {"id": payload.waiter_id, "cafe_id": cafe_id, "role": {"$in": _ROSTER_ROLES}}, {"_id": 0}
        )
        if not waiter or not waiter.get("is_active", True):
            raise HTTPException(status_code=404, detail="Staff member not found or inactive.")

    code = normalize_device_code(payload.code)
    activation = await db.device_activations.find_one({"code": code, "status": "pending"})
    if not activation or is_expired(activation["expires_at"]):
        raise HTTPException(status_code=400, detail="Invalid or expired code.")

    # Replace any prior authorization for this physical device.
    await db.device_activations.delete_many(
        {"device_id": activation["device_id"], "status": "active"}
    )
    device_name = payload.device_name or activation.get("device_name") or "Waiter device"
    await db.device_activations.update_one(
        {"_id": activation["_id"]},
        {
            "$set": {
                "user_id": payload.waiter_id,
                "cafe_id": cafe_id,
                "status": "active",
                "device_name": device_name,
                "activated_by": current_user.get("user_id"),
                "activated_at": utcnow().isoformat(),
            },
            "$unset": {"expires_at": ""},  # active rows must never be TTL-purged
        },
    )
    return {"success": True, "message": f'Device "{device_name}" activated.'}


@router.get("/waiters/devices")
async def list_devices(current_user: dict = Depends(MANAGEMENT)):
    """Active paired devices for the cafe, each with its assigned waiter (if any)."""
    rows = await db.device_activations.find(
        {"cafe_id": current_user["cafe_id"], "status": "active"}, {"_id": 0}
    ).to_list(1000)
    for r in rows:
        r["assigned_user"] = await _assigned_user(r)
    return rows


@router.patch("/waiters/devices/{activation_id}")
async def assign_device(activation_id: str, payload: DeviceAssign, current_user: dict = Depends(MANAGEMENT)):
    """Set/clear the current waiter on a device and/or rename it. user_id=None
    clears the assignment (device becomes ordering-only)."""
    cafe_id = current_user["cafe_id"]
    activation = await db.device_activations.find_one(
        {"id": activation_id, "cafe_id": cafe_id, "status": "active"}, {"_id": 0}
    )
    if not activation:
        raise HTTPException(status_code=404, detail="Device not found.")

    updates: dict = {}
    fields = payload.model_dump(exclude_unset=True)
    if "user_id" in fields:
        if fields["user_id"]:
            waiter = await db.users.find_one(
                {"id": fields["user_id"], "cafe_id": cafe_id, "role": {"$in": _ROSTER_ROLES}}, {"_id": 0}
            )
            if not waiter or not waiter.get("is_active", True):
                raise HTTPException(status_code=404, detail="Staff member not found or inactive.")
        updates["user_id"] = fields["user_id"]
    if "device_name" in fields and fields["device_name"]:
        updates["device_name"] = fields["device_name"].strip()

    if updates:
        await db.device_activations.update_one({"id": activation_id}, {"$set": updates})

    fresh = await db.device_activations.find_one({"id": activation_id}, {"_id": 0})
    fresh["assigned_user"] = await _assigned_user(fresh)
    return fresh


@router.post("/waiters/devices/logout")
async def logout_device(payload: DeviceLogout, current_user: dict = Depends(get_current_user)):
    """Device signs out: keep the pairing but mark it logged-out for the panel."""
    await db.device_activations.update_one(
        {"device_id": payload.device_id, "status": "active"},
        {"$set": {"signed_in": False, "last_logout": utcnow()}},
    )
    return {"message": "Signed out."}


@router.delete("/waiters/devices/{activation_id}")
async def revoke_device(activation_id: str, current_user: dict = Depends(MANAGEMENT)):
    result = await db.device_activations.delete_one(
        {"id": activation_id, "cafe_id": current_user["cafe_id"]}
    )
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Device not found.")
    return {"message": "Device revoked."}


# ---- Staff lifecycle ----

@router.post("/staff/{staff_id}/deactivate")
async def deactivate_staff(staff_id: str, current_user: dict = Depends(MANAGEMENT)):
    """Soft-disable a staff member and unassign them from any devices (which stay
    paired, just ordering-only until someone else is assigned)."""
    staff = await _find_staff_or_404(staff_id, current_user["cafe_id"])
    _guard_manager_boundary(current_user, staff)
    await db.users.update_one({"id": staff_id}, {"$set": {"is_active": False}})
    await db.device_activations.update_many({"user_id": staff_id}, {"$set": {"user_id": None}})
    return {"message": "Staff member deactivated."}


@router.post("/staff/{staff_id}/activate")
async def reactivate_staff(staff_id: str, current_user: dict = Depends(MANAGEMENT)):
    """Re-enable a previously deactivated staff member."""
    staff = await _find_staff_or_404(staff_id, current_user["cafe_id"])
    _guard_manager_boundary(current_user, staff)
    await db.users.update_one({"id": staff_id}, {"$set": {"is_active": True}})
    return {"message": "Staff member reactivated."}


@router.delete("/staff/{staff_id}")
async def delete_staff(staff_id: str, current_user: dict = Depends(MANAGEMENT)):
    """Delete a staff member; any devices they were on stay paired but unassigned."""
    staff = await _find_staff_or_404(staff_id, current_user["cafe_id"])
    _guard_manager_boundary(current_user, staff)
    await db.users.delete_one({"id": staff_id})
    await db.device_activations.update_many({"user_id": staff_id}, {"$set": {"user_id": None}})
    return {"message": "Staff member deleted."}
