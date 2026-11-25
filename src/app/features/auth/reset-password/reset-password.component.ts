import { Component, inject, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormBuilder, Validators } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { AuthService } from '../../../core/services/auth.service';

@Component({
  selector: 'app-reset-password',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterLink],
  templateUrl: './reset-password.component.html',
})
export class ResetPasswordComponent implements OnInit {
  private fb = inject(FormBuilder);
  private authService = inject(AuthService);
  private route = inject(ActivatedRoute);

  private token = '';
  successMessage = signal<string | null>(null);
  status = signal<'form' | 'success' | 'error'>('form');
  errorMessage = signal<string>('');

  resetForm = this.fb.group({
    newPassword: [
      '',
      [
        Validators.required,
        Validators.minLength(8),
        Validators.pattern(/^(?=.*[A-Za-z])(?=.*\d)/),
      ],
    ],
    confirmPassword: ['', Validators.required],
  });

  isLoading = this.authService.isLoading;
  error = this.authService.error;

  ngOnInit(): void {
    this.authService.clearError();
    this.token = this.route.snapshot.queryParams['token'] || '';

    if (!this.token) {
      this.status.set('error');
      this.errorMessage.set('Invalid reset link');
    }
  }

  onSubmit(): void {
    if (this.resetForm.invalid) {
      this.resetForm.markAllAsTouched();
      return;
    }

    const { newPassword, confirmPassword } = this.resetForm.value;

    if (newPassword !== confirmPassword) {
      this.authService.setError('Passwords do not match');
      return;
    }

    this.authService
      .resetPassword(this.token, newPassword ?? '')
      .subscribe({
        next: (response) => {
          this.successMessage.set(response.message);
          this.status.set('success');
        },
        error: (err) => {
          this.status.set('error');
          this.errorMessage.set(
            err.error?.error?.message || 'Reset failed',
          );
        },
      });
  }

  get f() {
    return this.resetForm.controls;
  }
}
