import { Injectable, inject, signal, computed } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, tap, map } from 'rxjs';
import { environment } from '../../../environments/environment';
import { ApiResponse, User, UserRole } from './auth.service';

export interface CreateUserRequest {
  name: string;
  email: string;
  password: string;
  role: UserRole;
  age?: number;
}

@Injectable({
  providedIn: 'root',
})
export class UserService {
  private http = inject(HttpClient);
  private apiUrl = environment.apiUrl;

  private usersSignal = signal<User[]>([]);
  private loadingSignal = signal<boolean>(false);
  private creatingSignal = signal<boolean>(false);
  private updatingUserIdSignal = signal<number | null>(null);
  private errorSignal = signal<string | null>(null);
  private successSignal = signal<string | null>(null);

  users = computed(() => this.usersSignal());
  isLoading = computed(() => this.loadingSignal());
  isCreating = computed(() => this.creatingSignal());
  updatingUserId = computed(() => this.updatingUserIdSignal());
  error = computed(() => this.errorSignal());
  successMessage = computed(() => this.successSignal());

  superAdminCount = computed(
    () => this.usersSignal().filter((u) => u.role === 'SuperAdmin').length,
  );
  adminCount = computed(
    () => this.usersSignal().filter((u) => u.role === 'Admin').length,
  );
  disabledCount = computed(
    () => this.usersSignal().filter((u) => u.isDisabled).length,
  );

  loadUsers(): Observable<User[]> {
    this.loadingSignal.set(true);
    this.errorSignal.set(null);

    return this.http.get<ApiResponse<User[]>>(`${this.apiUrl}/users`).pipe(
      tap({
        next: (response) => {
          this.usersSignal.set(response.data ?? []);
          this.loadingSignal.set(false);
        },
        error: (err) => {
          this.loadingSignal.set(false);
          this.errorSignal.set(
            err.error?.error?.message || 'Failed to load users',
          );
        },
      }),
      map((response) => response.data ?? []),
    );
  }

  createUser(payload: CreateUserRequest): Observable<User> {
    this.creatingSignal.set(true);
    this.errorSignal.set(null);
    this.successSignal.set(null);

    return this.http.post<ApiResponse<User>>(`${this.apiUrl}/users`, payload).pipe(
      tap({
        next: (response) => {
          if (response.data) {
            this.usersSignal.update((list) => [...list, response.data!]);
          }
          this.successSignal.set(response.message || 'User created');
          this.creatingSignal.set(false);
        },
        error: (err) => {
          this.creatingSignal.set(false);
          this.errorSignal.set(
            err.error?.error?.message || 'Failed to create user',
          );
        },
      }),
      map((response) => response.data!),
    );
  }

  updateRole(userId: number, role: UserRole): Observable<User> {
    this.updatingUserIdSignal.set(userId);
    this.errorSignal.set(null);
    this.successSignal.set(null);

    return this.http
      .patch<ApiResponse<User>>(`${this.apiUrl}/users/${userId}/role`, { role })
      .pipe(
        tap({
          next: (response) => {
            if (response.data) {
              this.usersSignal.update((list) =>
                list.map((u) => (u.id === userId ? response.data! : u)),
              );
            }
            this.successSignal.set(response.message || 'User role updated');
            this.updatingUserIdSignal.set(null);
          },
          error: (err) => {
            this.updatingUserIdSignal.set(null);
            this.errorSignal.set(
              err.error?.error?.message || 'Failed to update user role',
            );
          },
        }),
        map((response) => response.data!),
      );
  }

  toggleDisabled(userId: number, isDisabled: boolean): Observable<User> {
    this.updatingUserIdSignal.set(userId);
    this.errorSignal.set(null);
    this.successSignal.set(null);

    return this.http
      .patch<ApiResponse<User>>(`${this.apiUrl}/users/${userId}/status`, {
        isDisabled,
      })
      .pipe(
        tap({
          next: (response) => {
            if (response.data) {
              this.usersSignal.update((list) =>
                list.map((u) => (u.id === userId ? response.data! : u)),
              );
            }
            this.successSignal.set(response.message || 'User status updated');
            this.updatingUserIdSignal.set(null);
          },
          error: (err) => {
            this.updatingUserIdSignal.set(null);
            this.errorSignal.set(
              err.error?.error?.message || 'Failed to update user status',
            );
          },
        }),
        map((response) => response.data!),
      );
  }

  clearMessages(): void {
    this.errorSignal.set(null);
    this.successSignal.set(null);
  }
}
