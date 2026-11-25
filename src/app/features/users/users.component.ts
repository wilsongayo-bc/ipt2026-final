import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { AuthService, User, UserRole } from '../../core/services/auth.service';
import { UserService } from '../../core/services/user.service';

type UserFilter = 'all' | 'SuperAdmin' | 'Admin' | 'User' | 'disabled';

@Component({
  selector: 'app-users',
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './users.component.html',
})
export class UsersComponent implements OnInit {
  private authService = inject(AuthService);
  private userService = inject(UserService);

  currentUser = this.authService.currentUser;
  isSuperAdmin = this.authService.isSuperAdmin;
  users = this.userService.users;
  isLoading = this.userService.isLoading;
  updatingUserId = this.userService.updatingUserId;
  error = this.userService.error;
  successMessage = this.userService.successMessage;
  superAdminCount = this.userService.superAdminCount;
  adminCount = this.userService.adminCount;
  disabledCount = this.userService.disabledCount;

  searchQuery = signal<string>('');
  activeFilter = signal<UserFilter>('all');

  filteredUsers = computed(() => {
    const query = this.searchQuery().trim().toLowerCase();
    const filter = this.activeFilter();
    return this.users().filter((user) => {
      if (filter === 'SuperAdmin' && user.role !== 'SuperAdmin') {
        return false;
      }
      if (filter === 'Admin' && user.role !== 'Admin') {
        return false;
      }
      if (filter === 'User' && user.role !== 'User') {
        return false;
      }
      if (filter === 'disabled' && !user.isDisabled) {
        return false;
      }
      if (!query) {
        return true;
      }
      return (
        user.name.toLowerCase().includes(query) ||
        user.email.toLowerCase().includes(query)
      );
    });
  });

  ngOnInit(): void {
    this.userService.clearMessages();
    this.userService.loadUsers().subscribe({
      error: (err) => console.error('Failed to load users:', err),
    });
  }

  onSearch(event: Event): void {
    const input = event.target as HTMLInputElement;
    this.searchQuery.set(input.value);
  }

  setFilter(filter: UserFilter): void {
    this.activeFilter.set(filter);
  }

  canEditRole(target: User): boolean {
    const current = this.currentUser();
    if (!current || target.id === current.id) {
      return false;
    }
    if (target.role === 'SuperAdmin' && current.role !== 'SuperAdmin') {
      return false;
    }
    return true;
  }

  onRoleChange(user: User, event: Event): void {
    const select = event.target as HTMLSelectElement;
    const nextRole = select.value as UserRole;
    if (nextRole === user.role) {
      return;
    }

    if (!this.canEditRole(user)) {
      select.value = user.role;
      return;
    }

    this.userService.updateRole(user.id, nextRole).subscribe({
      error: () => {
        select.value = user.role;
      },
    });
  }

  toggleDisabled(user: User): void {
    if (user.role === 'Admin' || user.role === 'SuperAdmin') {
      return;
    }
    this.userService.toggleDisabled(user.id, !user.isDisabled).subscribe({
      error: (err) => console.error('Failed to update user status:', err),
    });
  }

  refresh(): void {
    this.userService.clearMessages();
    this.userService.loadUsers().subscribe();
  }

  logout(): void {
    this.authService.logout();
  }
}
