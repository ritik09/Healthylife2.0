# Generated by Django 2.2 on 2021-10-06 03:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('quickstart', '0003_auto_20211005_1526'),
    ]

    operations = [
        migrations.AlterField(
            model_name='doctor',
            name='image',
            field=models.ImageField(null='True', upload_to='static'),
        ),
        migrations.AlterField(
            model_name='user',
            name='image',
            field=models.ImageField(null='True', upload_to='static'),
        ),
    ]
