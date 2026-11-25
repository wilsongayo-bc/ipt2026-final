import { Component, inject, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormBuilder, Validators } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { AuthService } from '../../../core/services/auth.service';

@Component({
  selector: 'app-forgot-password',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterLink],
  templateUrl: './forgot-password.component.html',
})
export class ForgotPasswordComponent implements OnInit {
  private fb = inject(FormBuilder);
  private authService = inject(AuthService);
  private router = inject(Router);

  successMessage = signal<string | null>(null);
  previewUrl = signal<string | null>(null);

  forgotForm = this.fb.group({
    email: ['', [Validators.required, Validators.email]],
  });

  isLoading = this.authService.isLoading;
  error = this.authService.error;

  ngOnInit(): void {
    this.authService.clearError();
  }

  onSubmit(): void {
    if (this.forgotForm.invalid) {
      this.forgotForm.markAllAsTouched();
      return;
    }

    const { email } = this.forgotForm.value;

    this.authService.forgotPassword(email ?? '').subscribe({
      next: (response) => {
        this.successMessage.set(response.message);
        this.previewUrl.set(response.previewUrl ?? null);
      },
      error: (err) => {
        console.error('Forgot password failed:', err);
      },
    });
  }

  openPreviewLink(): void {
    const url = this.previewUrl();
    if (url) {
      void this.router.navigateByUrl(url);
    }
  }

  get f() {
    return this.forgotForm.controls;
  }
}
