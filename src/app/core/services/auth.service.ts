import { Injectable, inject, signal, computed } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable, tap, map, catchError, of, firstValueFrom } from 'rxjs';
import { environment } from '../../../environments/environment';

export type UserRole = 'SuperAdmin' | 'Admin' | 'User';

export interface User {
  id: number;
  name: string;
  email: string;
  age?: number;
  role: UserRole;
  isActive: boolean;
  isDisabled: boolean;
  createdAt: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  name: string;
  email: string;
  password: string;
  age?: number;
}

export interface AuthResponse {
  token: string;
  user: User;
}

export interface RegisterResponse {
  message: string;
  userId: number;
  previewUrl?: string;
}

export interface ForgotPasswordResponse {
  message: string;
  previewUrl?: string;
}

export interface ApiResponse<T> {
  success: boolean;
  message?: string;
  data?: T;
  error?: {
    code: string;
    message: string;
  };
}

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private http = inject(HttpClient);
  private router = inject(Router);
  private apiUrl = environment.apiUrl;

  // Reactive Signals (kept in memory; never persisted to localStorage)
  private currentUserSignal = signal<User | null>(null);
  private tokenSignal = signal<string | null>(null);
  private loadingSignal = signal<boolean>(false);
  private errorSignal = signal<string | null>(null);
  private unverifiedPreviewUrlSignal = signal<string | null>(null);

  // Computed Signals (Read-only public state)
  isLoggedIn = computed(() => !!this.tokenSignal() && !!this.currentUserSignal());
  currentUser = computed(() => this.currentUserSignal());
  isAdmin = computed(() => {
    const role = this.currentUserSignal()?.role;
    return role === 'Admin' || role === 'SuperAdmin';
  });
  isSuperAdmin = computed(() => this.currentUserSignal()?.role === 'SuperAdmin');
  currentToken = computed(() => this.tokenSignal());
  isLoading = computed(() => this.loadingSignal());
  error = computed(() => this.errorSignal());
  unverifiedPreviewUrl = computed(() => this.unverifiedPreviewUrlSignal());

  /**
   * Restore authenticated session from HttpOnly cookie on initial app load.
   */
  hydrateSession(): Promise<void> {
    return firstValueFrom(
      this.http.get<ApiResponse<AuthResponse>>(`${this.apiUrl}/auth/me`).pipe(
        tap((response) => {
          if (response.success && response.data) {
            this.tokenSignal.set(response.data.token);
            this.currentUserSignal.set(response.data.user);
          }
        }),
        map(() => undefined),
        catchError(() => of(undefined)),
      ),
    );
  }

  login(credentials: LoginRequest): Observable<AuthResponse> {
    this.loadingSignal.set(true);
    this.errorSignal.set(null);
    this.unverifiedPreviewUrlSignal.set(null);

    return this.http
      .post<ApiResponse<AuthResponse & { previewUrl?: string }>>(
        `${this.apiUrl}/auth/login`,
        credentials,
      )
      .pipe(
        tap({
          next: (response) => {
            if (response.success && response.data) {
              this.tokenSignal.set(response.data.token);
              this.currentUserSignal.set(response.data.user);
            }
            this.loadingSignal.set(false);
          },
          error: (err) => {
            this.loadingSignal.set(false);
            this.errorSignal.set(err.error?.error?.message || 'Login failed');
            const previewUrl = err.error?.data?.previewUrl;
            if (typeof previewUrl === 'string') {
              this.unverifiedPreviewUrlSignal.set(previewUrl);
            }
          },
        }),
        map((response) => response.data!),
      );
  }

  register(data: RegisterRequest): Observable<RegisterResponse> {
    this.loadingSignal.set(true);
    this.errorSignal.set(null);

    return this.http
      .post<ApiResponse<RegisterResponse>>(`${this.apiUrl}/auth/register`, data)
      .pipe(
        tap({
          next: () => {
            this.loadingSignal.set(false);
          },
          error: (err) => {
            this.loadingSignal.set(false);
            this.errorSignal.set(
              err.error?.error?.message || 'Registration failed',
            );
          },
        }),
        map((response) => ({
          message: response.data?.message || 'Registration successful',
          userId: response.data?.userId ?? 0,
          previewUrl: response.data?.previewUrl,
        })),
      );
  }

  verifyEmail(token: string): Observable<{ message: string }> {
    return this.http
      .get<ApiResponse<null>>(
        `${this.apiUrl}/auth/verify-email`,
        { params: { token } },
      )
      .pipe(
        map((response) => ({
          message: response.message || 'Email verified successfully',
        })),
      );
  }

  forgotPassword(email: string): Observable<ForgotPasswordResponse> {
    this.loadingSignal.set(true);
    this.errorSignal.set(null);

    return this.http
      .post<ApiResponse<{ previewUrl?: string }>>(
        `${this.apiUrl}/auth/forgot-password`,
        { email },
      )
      .pipe(
        tap({
          next: () => {
            this.loadingSignal.set(false);
          },
          error: (err) => {
            this.loadingSignal.set(false);
            this.errorSignal.set(
              err.error?.error?.message || 'Failed to request password reset',
            );
          },
        }),
        map((response) => ({
          message: response.message || 'Reset link sent',
          previewUrl: response.data?.previewUrl,
        })),
      );
  }

  resetPassword(token: string, newPassword: string): Observable<{ message: string }> {
    this.loadingSignal.set(true);
    this.errorSignal.set(null);

    return this.http
      .post<ApiResponse<null>>(`${this.apiUrl}/auth/reset-password`, {
        token,
        newPassword,
      })
      .pipe(
        tap({
          next: () => {
            this.loadingSignal.set(false);
          },
          error: (err) => {
            this.loadingSignal.set(false);
            this.errorSignal.set(
              err.error?.error?.message || 'Password reset failed',
            );
          },
        }),
        map((response) => ({
          message: response.message || 'Password reset successful',
        })),
      );
  }

  getCurrentUser(): Observable<User> {
    return this.http
      .get<ApiResponse<AuthResponse>>(`${this.apiUrl}/auth/me`)
      .pipe(
        tap((response) => {
          if (response.success && response.data) {
            this.currentUserSignal.set(response.data.user);
          }
        }),
        map((response) => response.data!.user),
      );
  }

  clearSession(): void {
    this.currentUserSignal.set(null);
    this.tokenSignal.set(null);
  }

  logout(): void {
    this.clearSession();
    this.http
      .post(`${this.apiUrl}/auth/logout`, {})
      .pipe(catchError(() => of(null)))
      .subscribe();
    void this.router.navigate(['/auth/login']);
  }

  setError(message: string): void {
    this.errorSignal.set(message);
  }

  clearError(): void {
    this.errorSignal.set(null);
    this.unverifiedPreviewUrlSignal.set(null);
  }
}
