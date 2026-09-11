import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("winfs", "0002_postgres_guards"),
    ]

    operations = [
        migrations.AlterField(
            model_name="winprincipal",
            name="user",
            field=models.OneToOneField(
                on_delete=django.db.models.deletion.RESTRICT,
                related_name="win_principal",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.RemoveConstraint(
            model_name="winace",
            name="win_ace_mask_nonneg",
        ),
        migrations.AddConstraint(
            model_name="winace",
            constraint=models.CheckConstraint(
                condition=models.Q(access_mask__gte=0, access_mask__lte=4294967295),
                name="win_ace_mask_32bit",
            ),
        ),
    ]
