<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use App\Models\OAuthAccessToken;

class ValidateOAuthToken
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json(['error' => 'No token provided'], 401);
        }

        $accessToken = OAuthAccessToken::where('access_token', $token)
                                     ->where('expires_at', '>', now())
                                     ->first();

        if (!$accessToken) {
            return response()->json(['error' => 'Invalid or expired token'], 401);
        }

        // Add user and token to request
        $request->merge([
            'oauth_token' => $accessToken,
            'oauth_user' => $accessToken->user
        ]);

        return $next($request);
    }
}
