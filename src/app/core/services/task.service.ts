import { Injectable, inject, signal, computed } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, tap, map } from 'rxjs';
import { environment } from '../../../environments/environment';
import { ApiResponse, User } from './auth.service';

export type TaskPriority = 'Low' | 'Medium' | 'High';
export type TaskStatus = 'Pending' | 'Done';

export interface TaskItem {
  id: number;
  userId: number;
  assigneeName: string;
  assigneeEmail: string;
  title: string;
  description: string;
  priority: TaskPriority;
  status: TaskStatus;
  dueDate?: string;
  isDisabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CreateTaskRequest {
  title: string;
  description?: string;
  priority: TaskPriority;
  dueDate?: string;
  userId?: number;
}

export interface UpdateTaskRequest {
  title?: string;
  description?: string;
  priority?: TaskPriority;
  status?: TaskStatus;
  dueDate?: string | null;
  userId?: number;
}

export interface TaskAiSummary {
  model: string;
  taskCount: number;
  generatedAt: string;
  overview: string;
  priorityFocus: string[];
  nextStepIdeas: string[];
}

@Injectable({
  providedIn: 'root',
})
export class TaskService {
  private http = inject(HttpClient);
  private apiUrl = environment.apiUrl;

  private tasksSignal = signal<TaskItem[]>([]);
  private assigneesSignal = signal<User[]>([]);
  private loadingSignal = signal<boolean>(false);
  private savingSignal = signal<boolean>(false);
  private updatingTaskIdSignal = signal<number | null>(null);
  private errorSignal = signal<string | null>(null);
  private successSignal = signal<string | null>(null);
  private aiSummarySignal = signal<TaskAiSummary | null>(null);
  private summarizingSignal = signal<boolean>(false);
  private aiErrorSignal = signal<string | null>(null);

  tasks = computed(() => this.tasksSignal());
  assignees = computed(() => this.assigneesSignal());
  isLoading = computed(() => this.loadingSignal());
  isSaving = computed(() => this.savingSignal());
  updatingTaskId = computed(() => this.updatingTaskIdSignal());
  error = computed(() => this.errorSignal());
  successMessage = computed(() => this.successSignal());
  aiSummary = computed(() => this.aiSummarySignal());
  isSummarizing = computed(() => this.summarizingSignal());
  aiError = computed(() => this.aiErrorSignal());

  pendingCount = computed(
    () =>
      this.tasksSignal().filter((t) => t.status === 'Pending' && !t.isDisabled)
        .length,
  );
  doneCount = computed(
    () =>
      this.tasksSignal().filter((t) => t.status === 'Done' && !t.isDisabled)
        .length,
  );
  disabledCount = computed(
    () => this.tasksSignal().filter((t) => t.isDisabled).length,
  );

  loadTasks(): Observable<TaskItem[]> {
    this.loadingSignal.set(true);
    this.errorSignal.set(null);

    return this.http.get<ApiResponse<TaskItem[]>>(`${this.apiUrl}/tasks`).pipe(
      tap({
        next: (response) => {
          this.tasksSignal.set(response.data ?? []);
          this.loadingSignal.set(false);
        },
        error: (err) => {
          this.loadingSignal.set(false);
          this.errorSignal.set(
            err.error?.error?.message || 'Failed to load tasks',
          );
        },
      }),
      map((response) => response.data ?? []),
    );
  }

  loadAssignees(): Observable<User[]> {
    return this.http.get<ApiResponse<User[]>>(`${this.apiUrl}/users`).pipe(
      tap({
        next: (response) => {
          const activeUsers = (response.data ?? []).filter((u) => !u.isDisabled);
          this.assigneesSignal.set(activeUsers);
        },
      }),
      map((response) => response.data ?? []),
    );
  }

  createTask(payload: CreateTaskRequest): Observable<TaskItem> {
    this.savingSignal.set(true);
    this.errorSignal.set(null);
    this.successSignal.set(null);

    return this.http
      .post<ApiResponse<TaskItem>>(`${this.apiUrl}/tasks`, payload)
      .pipe(
        tap({
          next: (response) => {
            if (response.data) {
              this.tasksSignal.update((list) => [response.data!, ...list]);
            }
            this.successSignal.set(response.message || 'Task created');
            this.savingSignal.set(false);
          },
          error: (err) => {
            this.savingSignal.set(false);
            this.errorSignal.set(
              err.error?.error?.message || 'Failed to create task',
            );
          },
        }),
        map((response) => response.data!),
      );
  }

  updateTask(taskId: number, payload: UpdateTaskRequest): Observable<TaskItem> {
    this.updatingTaskIdSignal.set(taskId);
    this.errorSignal.set(null);
    this.successSignal.set(null);

    return this.http
      .patch<ApiResponse<TaskItem>>(`${this.apiUrl}/tasks/${taskId}`, payload)
      .pipe(
        tap({
          next: (response) => {
            if (response.data) {
              this.tasksSignal.update((list) =>
                list.map((t) => (t.id === taskId ? response.data! : t)),
              );
            }
            this.successSignal.set(response.message || 'Task updated');
            this.updatingTaskIdSignal.set(null);
          },
          error: (err) => {
            this.updatingTaskIdSignal.set(null);
            this.errorSignal.set(
              err.error?.error?.message || 'Failed to update task',
            );
          },
        }),
        map((response) => response.data!),
      );
  }

  toggleDisabled(taskId: number, isDisabled: boolean): Observable<TaskItem> {
    this.updatingTaskIdSignal.set(taskId);
    this.errorSignal.set(null);
    this.successSignal.set(null);

    return this.http
      .patch<ApiResponse<TaskItem>>(`${this.apiUrl}/tasks/${taskId}/status`, {
        isDisabled,
      })
      .pipe(
        tap({
          next: (response) => {
            if (response.data) {
              this.tasksSignal.update((list) =>
                list.map((t) => (t.id === taskId ? response.data! : t)),
              );
            }
            this.successSignal.set(response.message || 'Task status updated');
            this.updatingTaskIdSignal.set(null);
          },
          error: (err) => {
            this.updatingTaskIdSignal.set(null);
            this.errorSignal.set(
              err.error?.error?.message || 'Failed to update task status',
            );
          },
        }),
        map((response) => response.data!),
      );
  }

  summarizeTasks(taskIds: number[]): Observable<TaskAiSummary> {
    this.summarizingSignal.set(true);
    this.aiErrorSignal.set(null);

    return this.http
      .post<ApiResponse<TaskAiSummary>>(`${this.apiUrl}/tasks/summarize`, {
        taskIds,
      })
      .pipe(
        tap({
          next: (response) => {
            if (response.data) {
              this.aiSummarySignal.set(response.data);
            }
            this.summarizingSignal.set(false);
          },
          error: (err) => {
            this.summarizingSignal.set(false);
            this.aiErrorSignal.set(
              err.error?.error?.message || 'Failed to summarize tasks with AI',
            );
          },
        }),
        map((response) => response.data!),
      );
  }

  clearAiSummary(): void {
    this.aiSummarySignal.set(null);
    this.aiErrorSignal.set(null);
  }

  clearMessages(): void {
    this.errorSignal.set(null);
    this.successSignal.set(null);
  }
}
