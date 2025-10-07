# Generated migration for context-aware BB84 sessions

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0004_activeeavesdropper_bb84session_accepted_at_and_more'),
    ]

    operations = [
        # Add context_type field
        migrations.AddField(
            model_name='bb84session',
            name='context_type',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('personal', 'Personal (one-on-one)'),
                    ('group', 'Group Context')
                ],
                default='personal',
                help_text="Whether this session is for personal or group communication"
            ),
        ),
        
        # Add group foreign key (nullable for personal sessions)
        migrations.AddField(
            model_name='bb84session',
            name='group',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='bb84_sessions',
                to='core.usergroup',
                help_text="Group this session belongs to (null for personal sessions)"
            ),
        ),
        
        # Remove old unique constraints if any
        migrations.AlterUniqueTogether(
            name='bb84session',
            unique_together=set(),
        ),
        
        # Add new unique constraint for context-aware sessions
        # This allows same sender-receiver pair to have multiple sessions (one per context)
        migrations.AddConstraint(
            model_name='bb84session',
            constraint=models.UniqueConstraint(
                fields=['sender', 'receiver', 'context_type', 'group'],
                name='unique_bb84_session_per_context'
            ),
        ),
    ]
