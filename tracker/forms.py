from django import forms
from .models import Ticket, Priority, UserDetail

class TicketForm(forms.ModelForm):
    class Meta:
        model = Ticket
        fields = ['subject', 'description', 'priority', 'status', 'assigned_to', 'brand']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Get priorities from the Priority table
        self.fields['priority'].queryset = Priority.objects.all()

class StaffTicketForm(forms.ModelForm):
    class Meta:
        model = Ticket
        fields = ['subject', 'description', 'priority', 'assigned_to']
        widgets = {
            'subject': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
            'priority': forms.Select(attrs={'class': 'form-control'}),
            'assigned_to': forms.Select(attrs={'class': 'form-control'})
        }

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.status = Ticket.STATUS_ACTIVE  # Set default status
        if commit:
            instance.save()
        return instance

    def clean(self):
        cleaned_data = super().clean()
        if not cleaned_data.get('subject'):
            raise forms.ValidationError('Subject is required')
        if not cleaned_data.get('description'):
            raise forms.ValidationError('Description is required')
        if not cleaned_data.get('priority'):
            raise forms.ValidationError('Priority is required')
        return cleaned_data