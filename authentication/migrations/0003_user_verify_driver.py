# Generated by Django 3.0.7 on 2021-05-13 22:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0002_user_is_staff'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='verify_driver',
            field=models.BooleanField(default=False),
        ),
    ]