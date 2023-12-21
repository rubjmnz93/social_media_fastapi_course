import logging

from fastapi import APIRouter, HTTPException, status

from src.database import database, user_table
from src.models.user import UserIn
from src.security import (
    get_user,
    get_password_hash,
    authenticate_user,
    create_access_token,
)

logger = logging.getLogger(__name__)


router = APIRouter()


@router.post("/register", status_code=201)
async def register(user: UserIn):
    logger.info("Registering a new user.", extra={"email": user.email})
    if await get_user(user.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with that email already exists.",
        )
    hashed_password = get_password_hash(user.password)
    query = user_table.insert().values(email=user.email, password=hashed_password)
    logger.debug(query)
    await database.execute(query)
    return {"detail": "User created."}


@router.post("/token")
async def login(user: UserIn):
    user = await authenticate_user(user.email, user.password)
    access_token = create_access_token(user.email)
    return {"access_token": access_token, "token_type": "bearer"}
