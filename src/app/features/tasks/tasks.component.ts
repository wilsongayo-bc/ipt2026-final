import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';
import {
  TaskItem,
  TaskPriority,
  TaskService,
  TaskStatus,
} from '../../core/services/task.service';

type StatusFilter = 'all' | TaskStatus;
type PriorityFilter = 'all' | TaskPriority;
type DisabledFilter = 'all' | 'active' | 'disabled';

@Component({
  selector: 'app-tasks',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterLink],
  templateUrl: './tasks.component.html',
})
export class TasksComponent implements OnInit {
  private fb = inject(FormBuilder);
  private authService = inject(AuthService);
  private taskService = inject(TaskService);

  currentUser = this.authService.currentUser;
  isAdmin = this.authService.isAdmin;

  tasks = this.taskService.tasks;
  assignees = this.taskService.assignees;
  isLoading = this.taskService.isLoading;
  isSaving = this.taskService.isSaving;
  updatingTaskId = this.taskService.updatingTaskId;
  error = this.taskService.error;
  successMessage = this.taskService.successMessage;
  aiSummary = this.taskService.aiSummary;
  isSummarizing = this.taskService.isSummarizing;
  aiError = this.taskService.aiError;
  pendingCount = this.taskService.pendingCount;
  doneCount = this.taskService.doneCount;
  disabledCount = this.taskService.disabledCount;

  showForm = signal<boolean>(false);
  editingTaskId = signal<number | null>(null);
  isSubmittingForm = computed(
    () =>
      this.isSaving() ||
      (this.editingTaskId() !== null &&
        this.updatingTaskId() === this.editingTaskId()),
  );

  searchQuery = signal<string>('');
  statusFilter = signal<StatusFilter>('all');
  priorityFilter = signal<PriorityFilter>('all');
  assigneeFilter = signal<number | 'all'>('all');
  disabledFilter = signal<DisabledFilter>('all');

  taskForm = this.fb.group({
    title: [
      '',
      [Validators.required, Validators.minLength(2), Validators.maxLength(140)],
    ],
    description: [''],
    priority: ['Medium' as TaskPriority, [Validators.required]],
    dueDate: [''],
    userId: [null as number | null],
  });

  filteredTasks = computed(() => {
    const query = this.searchQuery().trim().toLowerCase();
    const status = this.statusFilter();
    const priority = this.priorityFilter();
    const assignee = this.assigneeFilter();
    const disabled = this.disabledFilter();

    return this.tasks().filter((task) => {
      if (status !== 'all' && task.status !== status) {
        return false;
      }
      if (priority !== 'all' && task.priority !== priority) {
        return false;
      }
      if (assignee !== 'all' && task.userId !== assignee) {
        return false;
      }
      if (disabled === 'active' && task.isDisabled) {
        return false;
      }
      if (disabled === 'disabled' && !task.isDisabled) {
        return false;
      }
      if (!query) {
        return true;
      }
      return (
        task.title.toLowerCase().includes(query) ||
        task.description.toLowerCase().includes(query) ||
        task.assigneeName.toLowerCase().includes(query) ||
        task.assigneeEmail.toLowerCase().includes(query)
      );
    });
  });

  ngOnInit(): void {
    this.taskService.clearMessages();
    this.taskService.clearAiSummary();
    this.taskService.loadTasks().subscribe({
      error: (err) => console.error('Failed to load tasks:', err),
    });

    if (this.isAdmin()) {
      this.taskService.loadAssignees().subscribe({
        error: (err) => console.error('Failed to load assignees:', err),
      });
    }
  }

  summarizeFilteredTasks(): void {
    const taskIds = this.filteredTasks()
      .slice(0, 50)
      .map((task) => task.id);
    if (taskIds.length === 0 || this.isSummarizing()) {
      return;
    }
    this.taskService.summarizeTasks(taskIds).subscribe({
      error: (err) => console.error('Failed to summarize tasks:', err),
    });
  }

  dismissAiSummary(): void {
    this.taskService.clearAiSummary();
  }

  openCreateForm(): void {
    this.taskService.clearMessages();
    this.editingTaskId.set(null);
    this.taskForm.reset({
      title: '',
      description: '',
      priority: 'Medium',
      dueDate: '',
      userId: this.currentUser()?.id ?? null,
    });
    this.showForm.set(true);
  }

  openEditForm(task: TaskItem): void {
    if (!this.isAdmin() && task.isDisabled) {
      return;
    }
    this.taskService.clearMessages();
    this.editingTaskId.set(task.id);
    this.taskForm.reset({
      title: task.title,
      description: task.description,
      priority: task.priority,
      dueDate: task.dueDate ?? '',
      userId: task.userId,
    });
    this.showForm.set(true);
  }

  closeForm(): void {
    this.showForm.set(false);
    this.editingTaskId.set(null);
  }

  onSubmit(): void {
    if (this.taskForm.invalid) {
      this.taskForm.markAllAsTouched();
      return;
    }

    const { title, description, priority, dueDate, userId } =
      this.taskForm.value;
    const editingId = this.editingTaskId();

    if (editingId !== null) {
      this.taskService
        .updateTask(editingId, {
          title: title ?? '',
          description: description ?? '',
          priority: (priority as TaskPriority) ?? 'Medium',
          dueDate: dueDate ? dueDate : null,
          ...(this.isAdmin() && userId ? { userId: Number(userId) } : {}),
        })
        .subscribe({
          next: () => this.closeForm(),
          error: (err) => console.error('Failed to update task:', err),
        });
      return;
    }

    this.taskService
      .createTask({
        title: title ?? '',
        description: description ?? '',
        priority: (priority as TaskPriority) ?? 'Medium',
        dueDate: dueDate || undefined,
        ...(this.isAdmin() && userId ? { userId: Number(userId) } : {}),
      })
      .subscribe({
        next: () => this.closeForm(),
        error: (err) => console.error('Failed to create task:', err),
      });
  }

  toggleDone(task: TaskItem): void {
    if (task.isDisabled) {
      return;
    }
    const nextStatus: TaskStatus = task.status === 'Done' ? 'Pending' : 'Done';
    this.taskService.updateTask(task.id, { status: nextStatus }).subscribe({
      error: (err) => console.error('Failed to toggle task status:', err),
    });
  }

  toggleDisabled(task: TaskItem): void {
    if (!this.isAdmin()) {
      return;
    }
    this.taskService.toggleDisabled(task.id, !task.isDisabled).subscribe({
      error: (err) => console.error('Failed to disable/enable task:', err),
    });
  }

  onSearch(event: Event): void {
    this.searchQuery.set((event.target as HTMLInputElement).value);
  }

  setStatusFilter(status: StatusFilter): void {
    this.statusFilter.set(status);
  }

  onPriorityFilterChange(event: Event): void {
    this.priorityFilter.set(
      (event.target as HTMLSelectElement).value as PriorityFilter,
    );
  }

  onAssigneeFilterChange(event: Event): void {
    const val = (event.target as HTMLSelectElement).value;
    this.assigneeFilter.set(val === 'all' ? 'all' : Number(val));
  }

  onDisabledFilterChange(event: Event): void {
    this.disabledFilter.set(
      (event.target as HTMLSelectElement).value as DisabledFilter,
    );
  }

  refresh(): void {
    this.taskService.clearMessages();
    this.taskService.loadTasks().subscribe();
  }

  logout(): void {
    this.authService.logout();
  }

  get tf() {
    return this.taskForm.controls;
  }
}
