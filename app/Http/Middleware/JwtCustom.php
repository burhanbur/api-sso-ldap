<?php 
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

class JwtCustom
{
    public function handle(Request $request, Closure $next)
    {
        $token = null;

        // Cek Authorization header (Bearer)
        if ($request->bearerToken()) {
            $token = $request->bearerToken();
        }

        // Kalau tidak ada, cek cookie
        if (!$token && $request->hasCookie('access_token')) {
            $token = $request->cookie('access_token');
        }

        if (!$token) {
            throw new UnauthorizedHttpException('jwt-auth', 'Token not provided.');
        }

        try {
            JWTAuth::setToken($token);
            $user = JWTAuth::authenticate();

            if (!$user) {
                throw new UnauthorizedHttpException('jwt-auth', 'User not found.');
            }

            auth()->setUser($user);
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            throw new UnauthorizedHttpException('jwt-auth', 'Token expired.');
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            throw new UnauthorizedHttpException('jwt-auth', 'Invalid token.');
        }

        return $next($request);
    }
}