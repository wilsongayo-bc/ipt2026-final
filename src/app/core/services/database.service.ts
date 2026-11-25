import { Injectable, inject, signal, computed } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, tap, map } from 'rxjs';
import { environment } from '../../../environments/environment';
import { ApiResponse, AuthService, User } from './auth.service';

export type DatabaseEngine = 'sqlite' | 'mysql';

export interface MysqlSafeStatus {
  configured: boolean;
  host?: string;
  port?: number;
  database?: string;
  user?: string;
  ssl: boolean;
}

export interface DatabaseStatusInfo {
  activeEngine: DatabaseEngine;
  mysql: MysqlSafeStatus;
}

interface SwitchEngineResponse {
  status: DatabaseStatusInfo;
  token?: string;
  user?: User;
}

@Injectable({
  providedIn: 'root',
})
export class DatabaseService {
  private http = inject(HttpClient);
  private authService = inject(AuthService);
  private apiUrl = environment.apiUrl;

  private statusSignal = signal<DatabaseStatusInfo | null>(null);
  private loadingSignal = signal<boolean>(false);
  private testingSignal = signal<boolean>(false);
  private switchingSignal = signal<boolean>(false);
  private errorSignal = signal<string | null>(null);
  private successSignal = signal<string | null>(null);

  status = computed(() => this.statusSignal());
  activeEngine = computed(() => this.statusSignal()?.activeEngine ?? 'sqlite');
  isLoading = computed(() => this.loadingSignal());
  isTesting = computed(() => this.testingSignal());
  isSwitching = computed(() => this.switchingSignal());
  error = computed(() => this.errorSignal());
  successMessage = computed(() => this.successSignal());

  loadStatus(): Observable<DatabaseStatusInfo> {
    this.loadingSignal.set(true);
    this.errorSignal.set(null);

    return this.http
      .get<ApiResponse<DatabaseStatusInfo>>(`${this.apiUrl}/system/database`)
      .pipe(
        tap({
          next: (response) => {
            if (response.data) {
              this.statusSignal.set(response.data);
            }
            this.loadingSignal.set(false);
          },
          error: (err) => {
            this.loadingSignal.set(false);
            this.errorSignal.set(
              err.error?.error?.message || 'Failed to load database status',
            );
          },
        }),
        map((response) => response.data!),
      );
  }

  testMysql(): Observable<string> {
    this.testingSignal.set(true);
    this.errorSignal.set(null);
    this.successSignal.set(null);

    return this.http
      .post<ApiResponse<{ latencyMs: number; mysql: MysqlSafeStatus }>>(
        `${this.apiUrl}/system/database/test`,
        {},
      )
      .pipe(
        tap({
          next: (response) => {
            this.testingSignal.set(false);
            this.successSignal.set(
              response.message || 'Online MySQL connection succeeded.',
            );
          },
          error: (err) => {
            this.testingSignal.set(false);
            this.errorSignal.set(
              err.error?.error?.message || 'Online MySQL connection test failed',
            );
          },
        }),
        map((response) => response.message || 'Connected'),
      );
  }

  switchEngine(engine: DatabaseEngine): Observable<DatabaseStatusInfo> {
    this.switchingSignal.set(true);
    this.errorSignal.set(null);
    this.successSignal.set(null);

    return this.http
      .post<ApiResponse<SwitchEngineResponse>>(
        `${this.apiUrl}/system/database/engine`,
        { engine },
      )
      .pipe(
        tap({
          next: (response) => {
            if (response.data?.status) {
              this.statusSignal.set(response.data.status);
            }
            if (response.data?.token && response.data?.user) {
              this.authService.updateSession(
                response.data.token,
                response.data.user,
              );
            }
            this.successSignal.set(
              response.message || 'Database engine updated.',
            );
            this.switchingSignal.set(false);
          },
          error: (err) => {
            this.switchingSignal.set(false);
            this.errorSignal.set(
              err.error?.error?.message || 'Failed to switch database engine',
            );
          },
        }),
        map((response) => response.data!.status),
      );
  }

  clearMessages(): void {
    this.errorSignal.set(null);
    this.successSignal.set(null);
  }
}
