from django import forms
from .models import Ticket, Priority, UserDetail

class TicketForm(forms.ModelForm):
    class Meta:
        model = Ticket
        fields = ['subject', 'description', 'priority', 'assigned_to']
        widgets = {
            'subject': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter ticket subject'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Enter ticket description'
            }),
            'priority': forms.Select(attrs={
                'class': 'form-control'
            }),
            'assigned_to': forms.Select(attrs={
                'class': 'form-control'
            })
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Get all active priorities
        self.fields['priority'].queryset = Priority.objects.all().order_by('name')
        # Get all active users for assignee
        self.fields['assigned_to'].queryset = UserDetail.objects.filter(is_active=True).order_by('user_name')
        # Make priority required
        self.fields['priority'].required = True
        # Make assigned_to optional
        self.fields['assigned_to'].required = False
        self.fields['assigned_to'].empty_label = "--- Select Assignee ---"

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