import re
from pydantic import (
    BaseModel,
    EmailStr,
    Field,
    field_validator,
    model_validator
)

class UserCreate(BaseModel):
    username: str = Field(
        ...,
        min_length=4,
        max_length=20,
        pattern=r"^[a-zA-Z0-9]+$",
        description="Только буквы и цифры, 4–20 символов"
    )
    email: EmailStr
    password: str
    confirm_password: str
    age: int = Field(..., ge=18, le=100, description="Возраст от 18 до 100 лет")

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Пароль должен содержать минимум 8 символов")

        if not any(c.isupper() for c in value):
            raise ValueError("Пароль должен содержать хотя бы одну заглавную букву")

        if not any(c.isdigit() for c in value):
            raise ValueError("Пароль должен содержать хотя бы одну цифру")

        if not re.search(r"[!@#$%^&*]", value):
            raise ValueError("Пароль должен содержать хотя бы один спецсимвол: !@#$%^&*")

        return value

    @model_validator(mode="after")
    def check_passwords_match(self):
        if self.password != self.confirm_password:
            raise ValueError("Пароли не совпадают")
        return self