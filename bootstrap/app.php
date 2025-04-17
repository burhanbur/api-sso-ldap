<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;

use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenBlacklistedException;
use Tymon\JWTAuth\Exceptions\InvalidClaimException;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\PayloadException;
use Tymon\JWTAuth\Exceptions\UserNotDefinedException;

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
            'jwt.auth' => \Tymon\JWTAuth\Http\Middleware\Authenticate::class,
            'jwt.refresh' => \Tymon\JWTAuth\Http\Middleware\RefreshToken::class,
            'role' => \App\Http\Middleware\EnsureUserHasRole::class,
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
                
                return response()->json([
                    'success' => false,
                    'message' => $e->getMessage() ?? 'Internal Server Error',
                ], $statusCode);
            }
            
            return null;
        });
    })->create();
