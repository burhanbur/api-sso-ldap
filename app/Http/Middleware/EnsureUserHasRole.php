<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnsureUserHasRole
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next, ...$roles): Response
    {
        $user = auth()->user();

        if (!$user || !$user->roles()->whereIn('name', $roles)->exists()) {
            return response()->json([
                'message' => 'Unauthorized. Role required: ' . implode(', ', $roles)
            ], 403);
        }
        
        return $next($request);
    }
}
