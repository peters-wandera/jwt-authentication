

import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

interface LoginResponse {
  status: string;
  message: string;
  accessToken: string;
  refreshToken: string;
  tokenType: string;
  expiresIn: number;
}

interface RefreshResponse {
  status: string;
  message: string;
  accessToken: string;
  tokenType: string;
  expiresIn: number;
}

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App {
  private readonly http = inject(HttpClient);
  private readonly apiUrl = 'http://localhost:3000/api';

  username = 'admin';
  password = '';
  showPassword = false;
  loading = false;

  accessToken = '';
  refreshToken = '';

  errorMessage = '';
  successMessage = '';
  protectedMessage = '';
  loggedInUsername = '';

  async login(): Promise<void> {
    this.clearMessages();
    this.loading = true;

    try {
      const response = await firstValueFrom(
        this.http.post<LoginResponse>(
          `${this.apiUrl}/auth/login`,
          {
            username: this.username,
            password: this.password
          }
        )
      );

      this.accessToken = response.accessToken;
      this.refreshToken = response.refreshToken;
      this.loggedInUsername = this.username;

      this.password = '';
      this.successMessage = 'Login successful.';
    } catch (error) {
      this.errorMessage = this.getErrorMessage(
        error,
        'Unable to log in.'
      );
    } finally {
      this.loading = false;
    }
  }

  async loadProtectedData(): Promise<void> {
    this.clearMessages();
    this.loading = true;

    try {
      try {
        await this.requestProtectedData();
      } catch (error) {
        const httpError = error as HttpErrorResponse;

        if (httpError.status !== 401 || !this.refreshToken) {
          throw error;
        }

        // If the access token is no longer accepted,
        // try refreshing it before retrying the request.
        await this.refreshAccessToken();
        await this.requestProtectedData();
      }
    } catch (error) {
      this.errorMessage = this.getErrorMessage(
        error,
        'Could not access protected data.'
      );
    } finally {
      this.loading = false;
    }
  }

  private async requestProtectedData(): Promise<void> {
    const response = await firstValueFrom(
      this.http.get<{
        status: string;
        message: string;
        user: { username: string };
      }>(`${this.apiUrl}/auth/protected`, {
        headers: {
          Authorization: `Bearer ${this.accessToken}`
        }
      })
    );

    this.protectedMessage =
      `${response.message}. Authenticated as ${response.user.username}.`;
  }

  private async refreshAccessToken(): Promise<void> {
    const response = await firstValueFrom(
      this.http.post<RefreshResponse>(
        `${this.apiUrl}/auth/refresh`,
        { refreshToken: this.refreshToken }
      )
    );

    this.accessToken = response.accessToken;
    this.successMessage = 'Access token refreshed successfully.';
  }

  logout(): void {
    this.accessToken = '';
    this.refreshToken = '';
    this.loggedInUsername = '';
    this.protectedMessage = '';
    this.password = '';
    this.clearMessages();
    this.successMessage = 'You have logged out.';
  }

  togglePassword(): void {
    this.showPassword = !this.showPassword;
  }

  private clearMessages(): void {
    this.errorMessage = '';
    this.successMessage = '';
    this.protectedMessage = '';
  }

  private getErrorMessage(error: unknown, fallback: string): string {
    if (error instanceof HttpErrorResponse) {
      if (error.status === 0) {
        return 'Cannot connect to the backend. Check that it is running on port 3000.';
      }

      return error.error?.message || fallback;
    }

    return fallback;
  }
}




// import { Component, signal } from '@angular/core';
// import { RouterOutlet } from '@angular/router';

// @Component({
//   selector: 'app-root',
//   imports: [RouterOutlet],
//   templateUrl: './app.html',
//   styleUrl: './app.css'
// })
// export class App {
//   protected readonly title = signal('frontend');
// }
