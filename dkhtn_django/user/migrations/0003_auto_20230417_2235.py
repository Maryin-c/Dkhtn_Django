# Generated by Django 3.2.15 on 2023-04-17 14:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0002_user_avatar'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='email',
            field=models.CharField(max_length=32, unique=True, verbose_name='邮箱'),
        ),
    ]
