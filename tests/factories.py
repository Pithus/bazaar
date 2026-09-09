from typing import Any, Sequence

from django.contrib.auth import get_user_model
from factory import Faker, post_generation
from factory.django import DjangoModelFactory


class UserFactory(DjangoModelFactory):
    username = Faker("user_name")
    email = Faker("email")
    name = Faker("name")
    password = Faker(
        "password",
        length=42,
        special_chars=True,
        digits=True,
        upper_case=True,
        lower_case=True,
    )

    @post_generation
    def password(self, create: bool, extracted: Sequence[Any], **kwargs):  # noqa: F811
        if extracted:
            self.set_password(extracted)
        else:
            self.set_password(self.password)

    class Meta:
        model = get_user_model()
        django_get_or_create = ["username"]
        skip_postgeneration_save = True
