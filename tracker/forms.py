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
        fields = ['subject', 'description', 'priority', 'assigned_to', 'status']
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make priority a required field
        self.fields['priority'].required = True
        # Get priorities from the Priority model
        self.fields['priority'].queryset = Priority.objects.all()
        # Add Bootstrap classes
        for field in self.fields:
            self.fields[field].widget.attrs['class'] = 'form-control'
        # Add placeholder text
        self.fields['subject'].widget.attrs['placeholder'] = 'Enter ticket subject'
        self.fields['description'].widget.attrs['placeholder'] = 'Enter ticket description'