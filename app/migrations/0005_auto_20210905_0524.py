# Generated by Django 3.2.6 on 2021-09-05 05:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0004_auto_20210904_0829'),
    ]

    operations = [
        migrations.AlterField(
            model_name='image',
            name='desc1',
            field=models.CharField(blank=True, default='', max_length=255),
        ),
        migrations.AlterField(
            model_name='image',
            name='desc2',
            field=models.CharField(blank=True, default='', max_length=255),
        ),
    ]