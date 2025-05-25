document.addEventListener('DOMContentLoaded', function() {
    // Enable tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.classList.add('fade');
            alert.classList.remove('show');
        }, 5000);
    });

    // Form validation
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });

    // Timezone adjustment for datetime inputs
    const timeInputs = document.querySelectorAll('input[type="datetime-local"]');
    timeInputs.forEach(input => {
        // Convert UTC to local time for display
        if (input.value) {
            const date = new Date(input.value + 'Z');
            const localDateTime = date.toISOString().slice(0, 16);
            input.value = localDateTime;
        }
    });

    // Toggle user active status
    document.querySelectorAll('.toggle-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const userId = this.getAttribute('data-user-id');
            fetch(`/admin/users/${userId}/toggle`, {method: 'POST'})
                .then(res => res.json())
                .then(data => {
                    if(data.success) {
                        this.textContent = data.is_active ? 'Deactivate' : 'Activate';
                        this.classList.toggle('btn-warning', data.is_active);
                        this.classList.toggle('btn-success', !data.is_active);
                        // Update the status text
                        const statusSpan = document.getElementById('status-' + userId);
                        if (statusSpan) {
                            statusSpan.innerHTML = data.is_active
                                ? '<span class="text-success">Active</span>'
                                : '<span class="text-danger">Inactive</span>';
                        }
                    }
                });
        });
    });
});

// Security: Prevent form resubmission on refresh
if (window.history.replaceState) {
    window.history.replaceState(null, null, window.location.href);
}