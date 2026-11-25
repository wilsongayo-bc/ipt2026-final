import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';
import { AuthService } from '../services/auth.service';

export const errorInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  return next(req).pipe(
    catchError((error: HttpErrorResponse) => {
      const isLoginOrHydrate =
        req.url.includes('/auth/login') || req.url.includes('/auth/me');

      if (error.status === 401 && !isLoginOrHydrate) {
        authService.clearSession();
        void router.navigate(['/auth/login'], {
          queryParams: { returnUrl: router.url },
        });
      }

      if (error.status === 403) {
        console.error('Access denied:', error.error?.error?.message);
      }

      return throwError(() => error);
    }),
  );
};
