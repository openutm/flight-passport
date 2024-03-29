# Generated by Django 4.2.1 on 2023-06-12 13:13

from django.db import migrations, models
import oauth2_provider.generators
import oauth2_provider.models


class Migration(migrations.Migration):

    dependencies = [
        ('authprofiles', '0002_alter_passportapplication_client_class'),
    ]

    operations = [
        migrations.AddField(
            model_name='passportapplication',
            name='post_logout_redirect_uris',
            field=models.TextField(blank=True, help_text='Allowed Post Logout URIs list, space separated'),
        ),
        migrations.AlterField(
            model_name='passportapplication',
            name='client_class',
            field=models.IntegerField(choices=[(0, 'Other'), (1, 'Login only'), (2, 'Flight Spotlight Read - Write'), (3, 'Flight Blender Read - Write'), (4, 'Aerobridge Read and Write'), (5, 'Permission Signing Client')], default=0),
        ),
        migrations.AlterField(
            model_name='passportapplication',
            name='client_secret',
            field=oauth2_provider.models.ClientSecretField(blank=True, db_index=True, default=oauth2_provider.generators.generate_client_secret, help_text='Hashed on Save. Copy it now if this is a new secret.', max_length=255),
        ),
    ]
