import pytest

from bazaar.users.models import User
from tests.factories import UserFactory

@pytest.fixture(autouse=True)
def media_storage(settings, tmpdir):
    settings.MEDIA_ROOT = tmpdir.strpath

@pytest.fixture
def user() -> User:
    return UserFactory()
