<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use App\Traits\ApiResponse;

class EnsureSsoAdmin
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

        // Check if user has admin role for SSO application
        $hasAdminAccess = $user->userRoles()
            ->whereHas('application', function ($query) {
                $query->whereRaw('LOWER(code) = ?', ['sso']);
            })
            ->whereHas('role', function ($query) {
                $query->whereRaw('LOWER(name) = ?', ['admin']);
            })
            ->exists();

        if (!$hasAdminAccess) {
            return $this->errorResponse('Unauthorized. SSO admin access required.', 403);
        }

        return $next($request);
    }
}
