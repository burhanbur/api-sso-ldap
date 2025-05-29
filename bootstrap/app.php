<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;

use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->alias([
            'jwt.custom' => \App\Http\Middleware\JwtCustom::class,
            'jwt.auth' => \Tymon\JWTAuth\Http\Middleware\Authenticate::class,
            'jwt.refresh' => \Tymon\JWTAuth\Http\Middleware\RefreshToken::class,
            'sso.admin' => \App\Http\Middleware\EnsureSsoAdmin::class,
            'client.authorize' => \App\Http\Middleware\EnsureUserAppAccess::class,
            'oauth.token' => \App\Http\Middleware\ValidateOAuthToken::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions) {
        $exceptions->renderable(function (Throwable $e, Request $request) {
            if ($request->is('api/*') || $request->wantsJson()) {

                $statusCode = match (true) {
                    $e instanceof \Illuminate\Auth\AuthenticationException => 401,
                    $e instanceof \Illuminate\Auth\Access\AuthorizationException => 403,
                    $e instanceof \Illuminate\Database\Eloquent\ModelNotFoundException => 404,
                    $e instanceof \Symfony\Component\HttpKernel\Exception\NotFoundHttpException => 404,
                    $e instanceof \Illuminate\Validation\ValidationException => 422,

                    $e instanceof Tymon\JWTAuth\Exceptions\TokenInvalidException => 401,
                    $e instanceof Tymon\JWTAuth\Exceptions\TokenExpiredException => 401,
                    $e instanceof Tymon\JWTAuth\Exceptions\TokenBlacklistedException => 401,
                    $e instanceof Tymon\JWTAuth\Exceptions\InvalidClaimException => 401,
                    $e instanceof Tymon\JWTAuth\Exceptions\JWTException => 401,
                    $e instanceof Tymon\JWTAuth\Exceptions\PayloadException => 401,
                    $e instanceof Tymon\JWTAuth\Exceptions\UserNotDefinedException => 401,
                    $e instanceof Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException => 401,
                    default => 500,
                };

                if (env('APP_ENV') == 'live') {
                    if ($statusCode == 404) {
                        $message = 'The requested resource was not found.';
                    } elseif ($statusCode == 401) {
                        $message = 'Unauthorized access. Please login to continue.';
                    } elseif ($statusCode == 403) {
                        $message = 'Forbidden access. You do not have permission to perform this action.';
                    } elseif ($statusCode == 422) {
                        $message = 'Validation error. Please check your input.';
                    } else {
                        $message = 'An error occurred while processing your request. Please try again later.';
                    }
                    
                    Log::error($message, [
                        'url' => request()->url(),
                        'method' => request()->method(),
                        'timestamp' => now()->toDateTimeString(),
                    ]);
                } else {
                    $message = $e->getMessage() ?? 'Internal Server Error';
                }
        
                return response()->json([
                    'success' => false,
                    'message' => $message,
                    'url' => request()->url(),
                    'method' => request()->method(),
                    'timestamp' => now()->toDateTimeString(),
                ], $statusCode);
            }
            
            return null;
        });
    })->create();
