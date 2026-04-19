"""
Management command to create a superuser with a properly hashed password.

Usage:
    # Interactive (prompts for each value):
    python manage.py create_superuser_hashed

    # Non-interactive (all values supplied as arguments):
    python manage.py create_superuser_hashed \
        --username admin \
        --email admin@example.com \
        --password secret123

Background:
    Django stores passwords using its own hashing system (PBKDF2 by default).
    If a password is inserted into the database as plain text the user cannot
    log in, because Django's authentication layer will never find a match.
    This command uses django.contrib.auth.hashers.make_password() to produce
    the correct hash before saving, identical to what the built-in
    `createsuperuser` + `changepassword` flow does.

    Alternatively you can use Django's built-in commands:
        python manage.py createsuperuser          # creates user, prompts for password
        python manage.py changepassword <username> # resets an existing user's password
"""

import getpass

from django.contrib.auth.hashers import make_password
from django.core.management.base import BaseCommand, CommandError

from managers.models import AllUsers


class Command(BaseCommand):
    help = (
        "Create a superuser with a securely hashed password. "
        "Accepts --username, --email, and --password arguments; "
        "prompts interactively for any that are omitted."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--username",
            dest="username",
            default=None,
            help="Username for the new superuser.",
        )
        parser.add_argument(
            "--email",
            dest="email",
            default=None,
            help="Email address for the new superuser.",
        )
        parser.add_argument(
            "--password",
            dest="password",
            default=None,
            help=(
                "Password for the new superuser. "
                "Avoid passing this on the command line in production "
                "(it will appear in shell history). "
                "Omit the flag to be prompted securely instead."
            ),
        )

    def handle(self, *args, **options):
        username = options.get("username")
        email = options.get("email")
        password = options.get("password")

        # ── Collect missing values interactively ──────────────────────────
        if not username:
            username = input("Username: ").strip()
        if not username:
            raise CommandError("Username cannot be empty.")

        if AllUsers.objects.filter(username=username).exists():
            raise CommandError(
                f"A user with username '{username}' already exists. "
                "Use `python manage.py changepassword {username}` to reset "
                "their password, or choose a different username."
            )

        if not email:
            email = input("Email address: ").strip()

        if not password:
            password = getpass.getpass("Password: ")
            password_confirm = getpass.getpass("Password (again): ")
            if password != password_confirm:
                raise CommandError("Passwords do not match. Superuser not created.")

        if not password:
            raise CommandError("Password cannot be empty.")

        # ── Create the superuser with a hashed password ───────────────────
        user = AllUsers(
            username=username,
            email=email,
            is_staff=True,
            is_superuser=True,
            is_active=True,
        )
        user.password = make_password(password)
        user.save()

        self.stdout.write(
            self.style.SUCCESS(
                f"Superuser '{username}' created successfully with a hashed password.\n"
                "You can now log in at /admin/ using these credentials."
            )
        )
