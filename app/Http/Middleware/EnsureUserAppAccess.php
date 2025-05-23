<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use App\Traits\ApiResponse;

class EnsureUserAppAccess
{
    use ApiResponse;

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $user = auth()->user();

        if (!$user) {
            return $this->errorResponse('Unauthorized. User not authenticated.', 401);
        }

        $clientId = $request->header('x-api-key');

        if (!$clientId) {
            return $this->errorResponse('Application client ID is required.', 400);
        }

        // Check if user has access to the application
        $hasAccess = $user->userRoles()
            ->whereHas('application', function ($query) use ($clientId) {
                $query->where('client_id', $clientId)
                      ->where('is_active', true);
            })
            ->exists();

        if (!$hasAccess) {
            return $this->errorResponse('User does not have access to this application.', 403);
        }

        return $next($request);
    }
}
