import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './dashboard.component.html',
})
export class DashboardComponent {
  private authService = inject(AuthService);

  currentUser = this.authService.currentUser;
  isLoggedIn = this.authService.isLoggedIn;
  isAdmin = this.authService.isAdmin;
  refreshStatus = signal<string | null>(null);
  isRefreshing = signal<boolean>(false);

  refreshProfile(): void {
    this.isRefreshing.set(true);
    this.refreshStatus.set(null);
    this.authService.getCurrentUser().subscribe({
      next: () => {
        this.isRefreshing.set(false);
        this.refreshStatus.set('Session verified with /api/auth/me');
      },
      error: () => {
        this.isRefreshing.set(false);
      },
    });
  }

  logout(): void {
    this.authService.logout();
  }
}
