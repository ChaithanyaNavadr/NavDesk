from django import forms
from .models import Ticket, Priority, UserDetail

class StaffTicketForm(forms.ModelForm):
    priority = forms.ModelChoiceField(
        queryset=Priority.objects.all(),
        empty_label="Select Priority",
        widget=forms.Select(attrs={
            'class': 'form-control',
            'required': True
        })
    )
    
    assigned_to = forms.ModelChoiceField(
        queryset=UserDetail.objects.filter(is_active=True),
        empty_label="Select User",
        widget=forms.Select(attrs={
            'class': 'form-control',
            'required': True
        })
    )

    class Meta:
        model = Ticket
        fields = ['subject', 'description', 'priority', 'assigned_to']
        widgets = {
            'subject': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter ticket subject',
                'required': True
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Enter ticket description',
                'required': True
            })
        }