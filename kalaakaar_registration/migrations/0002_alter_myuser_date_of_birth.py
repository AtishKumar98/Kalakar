# Generated by Django 4.1.7 on 2023-03-19 11:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('kalaakaar_registration', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='myuser',
            name='date_of_birth',
            field=models.DateField(null=True),
        ),
    ]
