from django.db import migrations, models
import django.db.models.deletion
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('winfs', '0002_postgres_guards'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name='winprincipal',
            name='user',
            field=models.OneToOneField(
                on_delete=django.db.models.deletion.RESTRICT,
                related_name='win_principal',
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
