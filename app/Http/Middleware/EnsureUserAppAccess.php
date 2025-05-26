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
            return $this->errorResponse('Sesi Anda telah berakhir. Silakan login kembali.', 401);
        }

        $appId = $request->header('x-app-id');

        if (!$appId) {
            return $this->errorResponse('ID aplikasi wajib diisi.', 400);
        }

        // Check if user has access to the application
        $hasAccess = $user->userRoles()
            ->whereHas('application', function ($query) use ($appId) {
                $query->where('uuid', $appId)
                      ->where('is_active', true);
            })
            ->exists();

        if (!$hasAccess) {
            return $this->errorResponse('Anda tidak memiliki akses ke aplikasi ini.', 403);
        }

        return $next($request);
    }
}
